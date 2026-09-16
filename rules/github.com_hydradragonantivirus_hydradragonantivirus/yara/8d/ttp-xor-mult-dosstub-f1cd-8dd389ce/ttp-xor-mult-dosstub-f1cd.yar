rule TTP_XOR_MULT_DOSStub_f1cd {
  strings:
    $key_f1cd = { a5 a5 [2] d1 bd [2] 96 bf [2] d1 ae [2] 9f a2 [2] 93 a8 [2] 84 a3 [2] 9f ed [2] a2 }

  condition:
    any of them
}