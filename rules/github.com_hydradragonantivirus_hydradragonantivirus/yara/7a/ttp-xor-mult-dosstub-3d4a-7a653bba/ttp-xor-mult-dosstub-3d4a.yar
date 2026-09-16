rule TTP_XOR_MULT_DOSStub_3d4a {
  strings:
    $key_3d4a = { 69 22 [2] 1d 3a [2] 5a 38 [2] 1d 29 [2] 53 25 [2] 5f 2f [2] 48 24 [2] 53 6a [2] 6e }

  condition:
    any of them
}