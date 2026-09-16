rule TTP_XOR_MULT_DOSStub_3d48 {
  strings:
    $key_3d48 = { 69 20 [2] 1d 38 [2] 5a 3a [2] 1d 2b [2] 53 27 [2] 5f 2d [2] 48 26 [2] 53 68 [2] 6e }

  condition:
    any of them
}