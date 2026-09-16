rule TTP_XOR_MULT_DOSStub_3d38 {
  strings:
    $key_3d38 = { 69 50 [2] 1d 48 [2] 5a 4a [2] 1d 5b [2] 53 57 [2] 5f 5d [2] 48 56 [2] 53 18 [2] 6e }

  condition:
    any of them
}