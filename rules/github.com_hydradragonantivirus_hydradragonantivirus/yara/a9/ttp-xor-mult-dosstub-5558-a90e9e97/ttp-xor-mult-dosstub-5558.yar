rule TTP_XOR_MULT_DOSStub_5558 {
  strings:
    $key_5558 = { 01 30 [2] 75 28 [2] 32 2a [2] 75 3b [2] 3b 37 [2] 37 3d [2] 20 36 [2] 3b 78 [2] 06 }

  condition:
    any of them
}