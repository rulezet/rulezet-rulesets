rule TTP_XOR_MULT_DOSStub_2158 {
  strings:
    $key_2158 = { 75 30 [2] 01 28 [2] 46 2a [2] 01 3b [2] 4f 37 [2] 43 3d [2] 54 36 [2] 4f 78 [2] 72 }

  condition:
    any of them
}