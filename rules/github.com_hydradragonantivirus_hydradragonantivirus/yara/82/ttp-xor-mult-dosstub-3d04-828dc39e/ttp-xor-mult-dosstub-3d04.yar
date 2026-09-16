rule TTP_XOR_MULT_DOSStub_3d04 {
  strings:
    $key_3d04 = { 69 6c [2] 1d 74 [2] 5a 76 [2] 1d 67 [2] 53 6b [2] 5f 61 [2] 48 6a [2] 53 24 [2] 6e }

  condition:
    any of them
}