rule TTP_XOR_MULT_DOSStub_550a {
  strings:
    $key_550a = { 01 62 [2] 75 7a [2] 32 78 [2] 75 69 [2] 3b 65 [2] 37 6f [2] 20 64 [2] 3b 2a [2] 06 }

  condition:
    any of them
}