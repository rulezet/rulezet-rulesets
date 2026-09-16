rule TTP_XOR_MULT_DOSStub_584a {
  strings:
    $key_584a = { 0c 22 [2] 78 3a [2] 3f 38 [2] 78 29 [2] 36 25 [2] 3a 2f [2] 2d 24 [2] 36 6a [2] 0b }

  condition:
    any of them
}