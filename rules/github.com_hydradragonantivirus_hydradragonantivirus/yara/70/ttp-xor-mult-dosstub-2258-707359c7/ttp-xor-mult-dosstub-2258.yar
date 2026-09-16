rule TTP_XOR_MULT_DOSStub_2258 {
  strings:
    $key_2258 = { 76 30 [2] 02 28 [2] 45 2a [2] 02 3b [2] 4c 37 [2] 40 3d [2] 57 36 [2] 4c 78 [2] 71 }

  condition:
    any of them
}