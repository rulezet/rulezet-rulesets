rule TTP_XOR_MULT_DOSStub_42f4 {
  strings:
    $key_42f4 = { 16 9c [2] 62 84 [2] 25 86 [2] 62 97 [2] 2c 9b [2] 20 91 [2] 37 9a [2] 2c d4 [2] 11 }

  condition:
    any of them
}