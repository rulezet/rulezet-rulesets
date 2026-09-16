rule TTP_XOR_MULT_DOSStub_3d14 {
  strings:
    $key_3d14 = { 69 7c [2] 1d 64 [2] 5a 66 [2] 1d 77 [2] 53 7b [2] 5f 71 [2] 48 7a [2] 53 34 [2] 6e }

  condition:
    any of them
}