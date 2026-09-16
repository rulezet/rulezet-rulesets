rule TTP_XOR_MULT_DOSStub_42cd {
  strings:
    $key_42cd = { 16 a5 [2] 62 bd [2] 25 bf [2] 62 ae [2] 2c a2 [2] 20 a8 [2] 37 a3 [2] 2c ed [2] 11 }

  condition:
    any of them
}