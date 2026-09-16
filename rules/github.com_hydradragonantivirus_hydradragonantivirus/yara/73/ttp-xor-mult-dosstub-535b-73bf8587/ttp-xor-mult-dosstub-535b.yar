rule TTP_XOR_MULT_DOSStub_535b {
  strings:
    $key_535b = { 07 33 [2] 73 2b [2] 34 29 [2] 73 38 [2] 3d 34 [2] 31 3e [2] 26 35 [2] 3d 7b [2] 00 }

  condition:
    any of them
}