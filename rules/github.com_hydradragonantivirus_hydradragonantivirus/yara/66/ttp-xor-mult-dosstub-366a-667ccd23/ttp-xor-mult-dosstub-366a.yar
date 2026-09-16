rule TTP_XOR_MULT_DOSStub_366a {
  strings:
    $key_366a = { 62 02 [2] 16 1a [2] 51 18 [2] 16 09 [2] 58 05 [2] 54 0f [2] 43 04 [2] 58 4a [2] 65 }

  condition:
    any of them
}