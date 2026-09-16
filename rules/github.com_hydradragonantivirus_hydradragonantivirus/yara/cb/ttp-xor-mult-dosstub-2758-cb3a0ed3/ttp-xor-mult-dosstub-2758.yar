rule TTP_XOR_MULT_DOSStub_2758 {
  strings:
    $key_2758 = { 73 30 [2] 07 28 [2] 40 2a [2] 07 3b [2] 49 37 [2] 45 3d [2] 52 36 [2] 49 78 [2] 74 }

  condition:
    any of them
}