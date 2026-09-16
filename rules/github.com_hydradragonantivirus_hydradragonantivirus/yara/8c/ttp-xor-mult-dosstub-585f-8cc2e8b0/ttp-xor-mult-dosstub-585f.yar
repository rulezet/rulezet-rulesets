rule TTP_XOR_MULT_DOSStub_585f {
  strings:
    $key_585f = { 0c 37 [2] 78 2f [2] 3f 2d [2] 78 3c [2] 36 30 [2] 3a 3a [2] 2d 31 [2] 36 7f [2] 0b }

  condition:
    any of them
}