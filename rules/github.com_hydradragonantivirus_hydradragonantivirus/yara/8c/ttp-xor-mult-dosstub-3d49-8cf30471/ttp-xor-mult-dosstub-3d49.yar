rule TTP_XOR_MULT_DOSStub_3d49 {
  strings:
    $key_3d49 = { 69 21 [2] 1d 39 [2] 5a 3b [2] 1d 2a [2] 53 26 [2] 5f 2c [2] 48 27 [2] 53 69 [2] 6e }

  condition:
    any of them
}