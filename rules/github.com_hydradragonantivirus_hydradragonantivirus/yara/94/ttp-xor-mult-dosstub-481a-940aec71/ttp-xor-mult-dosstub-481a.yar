rule TTP_XOR_MULT_DOSStub_481a {
  strings:
    $key_481a = { 1c 72 [2] 68 6a [2] 2f 68 [2] 68 79 [2] 26 75 [2] 2a 7f [2] 3d 74 [2] 26 3a [2] 1b }

  condition:
    any of them
}