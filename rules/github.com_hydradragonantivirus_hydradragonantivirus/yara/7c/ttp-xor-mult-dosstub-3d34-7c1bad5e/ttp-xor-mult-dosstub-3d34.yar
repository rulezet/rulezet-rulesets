rule TTP_XOR_MULT_DOSStub_3d34 {
  strings:
    $key_3d34 = { 69 5c [2] 1d 44 [2] 5a 46 [2] 1d 57 [2] 53 5b [2] 5f 51 [2] 48 5a [2] 53 14 [2] 6e }

  condition:
    any of them
}