rule TTP_XOR_MULT_DOSStub_74f8 {
  strings:
    $key_74f8 = { 20 90 [2] 54 88 [2] 13 8a [2] 54 9b [2] 1a 97 [2] 16 9d [2] 01 96 [2] 1a d8 [2] 27 }

  condition:
    any of them
}