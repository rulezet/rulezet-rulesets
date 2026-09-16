rule TTP_XOR_MULT_DOSStub_3d72 {
  strings:
    $key_3d72 = { 69 1a [2] 1d 02 [2] 5a 00 [2] 1d 11 [2] 53 1d [2] 5f 17 [2] 48 1c [2] 53 52 [2] 6e }

  condition:
    any of them
}