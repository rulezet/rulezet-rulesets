rule TTP_XOR_MULT_DOSStub_440a {
  strings:
    $key_440a = { 10 62 [2] 64 7a [2] 23 78 [2] 64 69 [2] 2a 65 [2] 26 6f [2] 31 64 [2] 2a 2a [2] 17 }

  condition:
    any of them
}