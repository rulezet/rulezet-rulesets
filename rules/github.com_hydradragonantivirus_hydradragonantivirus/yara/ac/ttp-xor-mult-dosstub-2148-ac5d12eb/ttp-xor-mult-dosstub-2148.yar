rule TTP_XOR_MULT_DOSStub_2148 {
  strings:
    $key_2148 = { 75 20 [2] 01 38 [2] 46 3a [2] 01 2b [2] 4f 27 [2] 43 2d [2] 54 26 [2] 4f 68 [2] 72 }

  condition:
    any of them
}