rule TTP_XOR_MULT_DOSStub_e1cd {
  strings:
    $key_e1cd = { b5 a5 [2] c1 bd [2] 86 bf [2] c1 ae [2] 8f a2 [2] 83 a8 [2] 94 a3 [2] 8f ed [2] b2 }

  condition:
    any of them
}