rule TTP_XOR_MULT_DOSStub_54cd {
  strings:
    $key_54cd = { 00 a5 [2] 74 bd [2] 33 bf [2] 74 ae [2] 3a a2 [2] 36 a8 [2] 21 a3 [2] 3a ed [2] 07 }

  condition:
    any of them
}