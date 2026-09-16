rule TTP_XOR_MULT_DOSStub_537b {
  strings:
    $key_537b = { 07 13 [2] 73 0b [2] 34 09 [2] 73 18 [2] 3d 14 [2] 31 1e [2] 26 15 [2] 3d 5b [2] 00 }

  condition:
    any of them
}