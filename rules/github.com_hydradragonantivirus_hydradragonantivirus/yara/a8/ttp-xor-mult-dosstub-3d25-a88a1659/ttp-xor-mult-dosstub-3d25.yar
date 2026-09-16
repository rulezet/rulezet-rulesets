rule TTP_XOR_MULT_DOSStub_3d25 {
  strings:
    $key_3d25 = { 69 4d [2] 1d 55 [2] 5a 57 [2] 1d 46 [2] 53 4a [2] 5f 40 [2] 48 4b [2] 53 05 [2] 6e }

  condition:
    any of them
}