rule TTP_XOR_MULT_DOSStub_2155 {
  strings:
    $key_2155 = { 75 3d [2] 01 25 [2] 46 27 [2] 01 36 [2] 4f 3a [2] 43 30 [2] 54 3b [2] 4f 75 [2] 72 }

  condition:
    any of them
}