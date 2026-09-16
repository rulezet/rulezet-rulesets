rule TTP_XOR_MULT_DOSStub_5658 {
  strings:
    $key_5658 = { 02 30 [2] 76 28 [2] 31 2a [2] 76 3b [2] 38 37 [2] 34 3d [2] 23 36 [2] 38 78 [2] 05 }

  condition:
    any of them
}