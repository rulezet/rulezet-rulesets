rule TTP_XOR_MULT_DOSStub_3d7a {
  strings:
    $key_3d7a = { 69 12 [2] 1d 0a [2] 5a 08 [2] 1d 19 [2] 53 15 [2] 5f 1f [2] 48 14 [2] 53 5a [2] 6e }

  condition:
    any of them
}