rule TTP_XOR_MULT_DOSStub_1658 {
  strings:
    $key_1658 = { 42 30 [2] 36 28 [2] 71 2a [2] 36 3b [2] 78 37 [2] 74 3d [2] 63 36 [2] 78 78 [2] 45 }

  condition:
    any of them
}