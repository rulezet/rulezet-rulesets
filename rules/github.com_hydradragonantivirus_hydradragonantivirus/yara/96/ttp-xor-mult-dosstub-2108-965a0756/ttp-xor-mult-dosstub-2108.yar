rule TTP_XOR_MULT_DOSStub_2108 {
  strings:
    $key_2108 = { 75 60 [2] 01 78 [2] 46 7a [2] 01 6b [2] 4f 67 [2] 43 6d [2] 54 66 [2] 4f 28 [2] 72 }

  condition:
    any of them
}