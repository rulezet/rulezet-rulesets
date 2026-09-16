rule TTP_XOR_MULT_DOSStub_2245 {
  strings:
    $key_2245 = { 76 2d [2] 02 35 [2] 45 37 [2] 02 26 [2] 4c 2a [2] 40 20 [2] 57 2b [2] 4c 65 [2] 71 }

  condition:
    any of them
}