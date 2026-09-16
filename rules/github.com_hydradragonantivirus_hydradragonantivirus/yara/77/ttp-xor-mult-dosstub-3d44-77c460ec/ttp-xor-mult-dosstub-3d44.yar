rule TTP_XOR_MULT_DOSStub_3d44 {
  strings:
    $key_3d44 = { 69 2c [2] 1d 34 [2] 5a 36 [2] 1d 27 [2] 53 2b [2] 5f 21 [2] 48 2a [2] 53 64 [2] 6e }

  condition:
    any of them
}