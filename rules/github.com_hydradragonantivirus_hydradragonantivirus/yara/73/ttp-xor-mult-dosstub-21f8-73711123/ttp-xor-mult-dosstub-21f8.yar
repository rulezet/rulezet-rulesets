rule TTP_XOR_MULT_DOSStub_21f8 {
  strings:
    $key_21f8 = { 75 90 [2] 01 88 [2] 46 8a [2] 01 9b [2] 4f 97 [2] 43 9d [2] 54 96 [2] 4f d8 [2] 72 }

  condition:
    any of them
}