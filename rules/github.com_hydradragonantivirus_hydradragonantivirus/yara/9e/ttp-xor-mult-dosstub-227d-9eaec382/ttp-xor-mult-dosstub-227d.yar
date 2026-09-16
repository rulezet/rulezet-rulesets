rule TTP_XOR_MULT_DOSStub_227d {
  strings:
    $key_227d = { 76 15 [2] 02 0d [2] 45 0f [2] 02 1e [2] 4c 12 [2] 40 18 [2] 57 13 [2] 4c 5d [2] 71 }

  condition:
    any of them
}