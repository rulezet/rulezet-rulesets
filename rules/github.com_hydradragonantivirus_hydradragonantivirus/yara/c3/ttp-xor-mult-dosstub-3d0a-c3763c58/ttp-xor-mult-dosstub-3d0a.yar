rule TTP_XOR_MULT_DOSStub_3d0a {
  strings:
    $key_3d0a = { 69 62 [2] 1d 7a [2] 5a 78 [2] 1d 69 [2] 53 65 [2] 5f 6f [2] 48 64 [2] 53 2a [2] 6e }

  condition:
    any of them
}