rule TTP_XOR_MULT_DOSStub_587a {
  strings:
    $key_587a = { 0c 12 [2] 78 0a [2] 3f 08 [2] 78 19 [2] 36 15 [2] 3a 1f [2] 2d 14 [2] 36 5a [2] 0b }

  condition:
    any of them
}