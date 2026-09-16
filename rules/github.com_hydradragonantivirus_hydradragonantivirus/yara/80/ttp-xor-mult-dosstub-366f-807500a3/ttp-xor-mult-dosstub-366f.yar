rule TTP_XOR_MULT_DOSStub_366f {
  strings:
    $key_366f = { 62 07 [2] 16 1f [2] 51 1d [2] 16 0c [2] 58 00 [2] 54 0a [2] 43 01 [2] 58 4f [2] 65 }

  condition:
    any of them
}