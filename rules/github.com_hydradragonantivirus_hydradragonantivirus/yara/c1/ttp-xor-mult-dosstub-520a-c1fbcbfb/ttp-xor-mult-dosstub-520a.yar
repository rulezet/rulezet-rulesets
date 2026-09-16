rule TTP_XOR_MULT_DOSStub_520a {
  strings:
    $key_520a = { 06 62 [2] 72 7a [2] 35 78 [2] 72 69 [2] 3c 65 [2] 30 6f [2] 27 64 [2] 3c 2a [2] 01 }

  condition:
    any of them
}