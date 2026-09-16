rule TTP_XOR_MULT_DOSStub_3d68 {
  strings:
    $key_3d68 = { 69 00 [2] 1d 18 [2] 5a 1a [2] 1d 0b [2] 53 07 [2] 5f 0d [2] 48 06 [2] 53 48 [2] 6e }

  condition:
    any of them
}