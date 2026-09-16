rule TTP_XOR_MULT_DOSStub_3d08 {
  strings:
    $key_3d08 = { 69 60 [2] 1d 78 [2] 5a 7a [2] 1d 6b [2] 53 67 [2] 5f 6d [2] 48 66 [2] 53 28 [2] 6e }

  condition:
    any of them
}