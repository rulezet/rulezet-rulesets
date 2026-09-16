rule TTP_XOR_MULT_DOSStub_52f8 {
  strings:
    $key_52f8 = { 06 90 [2] 72 88 [2] 35 8a [2] 72 9b [2] 3c 97 [2] 30 9d [2] 27 96 [2] 3c d8 [2] 01 }

  condition:
    any of them
}