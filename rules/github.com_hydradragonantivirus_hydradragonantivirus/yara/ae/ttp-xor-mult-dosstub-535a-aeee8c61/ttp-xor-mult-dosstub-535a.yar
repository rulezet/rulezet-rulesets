rule TTP_XOR_MULT_DOSStub_535a {
  strings:
    $key_535a = { 07 32 [2] 73 2a [2] 34 28 [2] 73 39 [2] 3d 35 [2] 31 3f [2] 26 34 [2] 3d 7a [2] 00 }

  condition:
    any of them
}