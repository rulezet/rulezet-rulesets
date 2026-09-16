rule TTP_XOR_MULT_DOSStub_1424 {
  strings:
    $key_1424 = { 40 4c [2] 34 54 [2] 73 56 [2] 34 47 [2] 7a 4b [2] 76 41 [2] 61 4a [2] 7a 04 [2] 47 }

  condition:
    any of them
}