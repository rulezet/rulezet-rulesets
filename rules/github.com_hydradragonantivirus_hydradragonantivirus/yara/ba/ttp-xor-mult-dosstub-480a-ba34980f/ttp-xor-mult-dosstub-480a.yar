rule TTP_XOR_MULT_DOSStub_480a {
  strings:
    $key_480a = { 1c 62 [2] 68 7a [2] 2f 78 [2] 68 69 [2] 26 65 [2] 2a 6f [2] 3d 64 [2] 26 2a [2] 1b }

  condition:
    any of them
}