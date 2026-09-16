rule TTP_XOR_MULT_DOSStub_1d48 {
  strings:
    $key_1d48 = { 49 20 [2] 3d 38 [2] 7a 3a [2] 3d 2b [2] 73 27 [2] 7f 2d [2] 68 26 [2] 73 68 [2] 4e }

  condition:
    any of them
}