rule TTP_XOR_MULT_DOSStub_5a04 {
  strings:
    $key_5a04 = { 0e 6c [2] 7a 74 [2] 3d 76 [2] 7a 67 [2] 34 6b [2] 38 61 [2] 2f 6a [2] 34 24 [2] 09 }

  condition:
    any of them
}