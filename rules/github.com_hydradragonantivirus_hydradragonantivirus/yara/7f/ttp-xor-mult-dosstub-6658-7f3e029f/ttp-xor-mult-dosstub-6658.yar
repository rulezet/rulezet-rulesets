rule TTP_XOR_MULT_DOSStub_6658 {
  strings:
    $key_6658 = { 32 30 [2] 46 28 [2] 01 2a [2] 46 3b [2] 08 37 [2] 04 3d [2] 13 36 [2] 08 78 [2] 35 }

  condition:
    any of them
}