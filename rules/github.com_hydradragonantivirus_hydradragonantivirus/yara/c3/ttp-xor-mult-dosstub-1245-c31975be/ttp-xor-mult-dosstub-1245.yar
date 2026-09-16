rule TTP_XOR_MULT_DOSStub_1245 {
  strings:
    $key_1245 = { 46 2d [2] 32 35 [2] 75 37 [2] 32 26 [2] 7c 2a [2] 70 20 [2] 67 2b [2] 7c 65 [2] 41 }

  condition:
    any of them
}