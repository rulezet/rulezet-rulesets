rule TTP_XOR_MULT_DOSStub_582a {
  strings:
    $key_582a = { 0c 42 [2] 78 5a [2] 3f 58 [2] 78 49 [2] 36 45 [2] 3a 4f [2] 2d 44 [2] 36 0a [2] 0b }

  condition:
    any of them
}