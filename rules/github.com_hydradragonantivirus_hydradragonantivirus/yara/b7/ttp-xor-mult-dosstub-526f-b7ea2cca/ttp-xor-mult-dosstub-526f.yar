rule TTP_XOR_MULT_DOSStub_526f {
  strings:
    $key_526f = { 06 07 [2] 72 1f [2] 35 1d [2] 72 0c [2] 3c 00 [2] 30 0a [2] 27 01 [2] 3c 4f [2] 01 }

  condition:
    any of them
}