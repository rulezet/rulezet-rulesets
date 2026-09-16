rule TTP_XOR_MULT_DOSStub_534b {
  strings:
    $key_534b = { 07 23 [2] 73 3b [2] 34 39 [2] 73 28 [2] 3d 24 [2] 31 2e [2] 26 25 [2] 3d 6b [2] 00 }

  condition:
    any of them
}