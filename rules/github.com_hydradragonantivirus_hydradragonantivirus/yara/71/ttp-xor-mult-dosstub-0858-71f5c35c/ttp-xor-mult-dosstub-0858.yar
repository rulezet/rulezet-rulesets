rule TTP_XOR_MULT_DOSStub_0858 {
  strings:
    $key_0858 = { 5c 30 [2] 28 28 [2] 6f 2a [2] 28 3b [2] 66 37 [2] 6a 3d [2] 7d 36 [2] 66 78 [2] 5b }

  condition:
    any of them
}