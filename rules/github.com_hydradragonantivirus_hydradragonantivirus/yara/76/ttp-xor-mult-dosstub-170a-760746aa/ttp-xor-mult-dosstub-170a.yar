rule TTP_XOR_MULT_DOSStub_170a {
  strings:
    $key_170a = { 43 62 [2] 37 7a [2] 70 78 [2] 37 69 [2] 79 65 [2] 75 6f [2] 62 64 [2] 79 2a [2] 44 }

  condition:
    any of them
}