rule TTP_XOR_MULT_DOSStub_5124 {
  strings:
    $key_5124 = { 05 4c [2] 71 54 [2] 36 56 [2] 71 47 [2] 3f 4b [2] 33 41 [2] 24 4a [2] 3f 04 [2] 02 }

  condition:
    any of them
}