rule TTP_XOR_MULT_DOSStub_185f {
  strings:
    $key_185f = { 4c 37 [2] 38 2f [2] 7f 2d [2] 38 3c [2] 76 30 [2] 7a 3a [2] 6d 31 [2] 76 7f [2] 4b }

  condition:
    any of them
}