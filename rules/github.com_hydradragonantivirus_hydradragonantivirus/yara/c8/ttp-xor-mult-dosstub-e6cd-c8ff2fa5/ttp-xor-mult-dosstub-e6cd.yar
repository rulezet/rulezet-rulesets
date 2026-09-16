rule TTP_XOR_MULT_DOSStub_e6cd {
  strings:
    $key_e6cd = { b2 a5 [2] c6 bd [2] 81 bf [2] c6 ae [2] 88 a2 [2] 84 a8 [2] 93 a3 [2] 88 ed [2] b5 }

  condition:
    any of them
}