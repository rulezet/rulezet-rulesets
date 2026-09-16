rule TTP_XOR_MULT_DOSStub_5d5f {
  strings:
    $key_5d5f = { 09 37 [2] 7d 2f [2] 3a 2d [2] 7d 3c [2] 33 30 [2] 3f 3a [2] 28 31 [2] 33 7f [2] 0e }

  condition:
    any of them
}