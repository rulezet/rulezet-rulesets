rule TTP_XOR_MULT_DOSStub_1d1a {
  strings:
    $key_1d1a = { 49 72 [2] 3d 6a [2] 7a 68 [2] 3d 79 [2] 73 75 [2] 7f 7f [2] 68 74 [2] 73 3a [2] 4e }

  condition:
    any of them
}