rule TTP_XOR_MULT_DOSStub_580a {
  strings:
    $key_580a = { 0c 62 [2] 78 7a [2] 3f 78 [2] 78 69 [2] 36 65 [2] 3a 6f [2] 2d 64 [2] 36 2a [2] 0b }

  condition:
    any of them
}