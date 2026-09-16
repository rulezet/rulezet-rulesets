rule TTP_XOR_MULT_DOSStub_225f {
  strings:
    $key_225f = { 76 37 [2] 02 2f [2] 45 2d [2] 02 3c [2] 4c 30 [2] 40 3a [2] 57 31 [2] 4c 7f [2] 71 }

  condition:
    any of them
}