rule TTP_XOR_MULT_DOSStub_3d05 {
  strings:
    $key_3d05 = { 69 6d [2] 1d 75 [2] 5a 77 [2] 1d 66 [2] 53 6a [2] 5f 60 [2] 48 6b [2] 53 25 [2] 6e }

  condition:
    any of them
}