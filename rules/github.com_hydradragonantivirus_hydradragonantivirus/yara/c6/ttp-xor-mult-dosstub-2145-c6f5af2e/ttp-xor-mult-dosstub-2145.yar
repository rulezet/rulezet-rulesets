rule TTP_XOR_MULT_DOSStub_2145 {
  strings:
    $key_2145 = { 75 2d [2] 01 35 [2] 46 37 [2] 01 26 [2] 4f 2a [2] 43 20 [2] 54 2b [2] 4f 65 [2] 72 }

  condition:
    any of them
}