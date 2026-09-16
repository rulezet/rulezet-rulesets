rule TTP_XOR_MULT_DOSStub_7a0a {
  strings:
    $key_7a0a = { 2e 62 [2] 5a 7a [2] 1d 78 [2] 5a 69 [2] 14 65 [2] 18 6f [2] 0f 64 [2] 14 2a [2] 29 }

  condition:
    any of them
}