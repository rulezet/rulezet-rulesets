rule TTP_XOR_MULT_DOSStub_7424 {
  strings:
    $key_7424 = { 20 4c [2] 54 54 [2] 13 56 [2] 54 47 [2] 1a 4b [2] 16 41 [2] 01 4a [2] 1a 04 [2] 27 }

  condition:
    any of them
}