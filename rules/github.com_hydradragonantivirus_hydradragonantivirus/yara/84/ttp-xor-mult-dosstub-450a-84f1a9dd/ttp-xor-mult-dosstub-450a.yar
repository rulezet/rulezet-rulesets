rule TTP_XOR_MULT_DOSStub_450a {
  strings:
    $key_450a = { 11 62 [2] 65 7a [2] 22 78 [2] 65 69 [2] 2b 65 [2] 27 6f [2] 30 64 [2] 2b 2a [2] 16 }

  condition:
    any of them
}