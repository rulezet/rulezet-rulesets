rule TTP_XOR_MULT_DOSStub_483a {
  strings:
    $key_483a = { 1c 52 [2] 68 4a [2] 2f 48 [2] 68 59 [2] 26 55 [2] 2a 5f [2] 3d 54 [2] 26 1a [2] 1b }

  condition:
    any of them
}