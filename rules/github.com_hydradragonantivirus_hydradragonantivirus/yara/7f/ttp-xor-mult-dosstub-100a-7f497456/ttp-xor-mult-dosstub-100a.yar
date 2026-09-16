rule TTP_XOR_MULT_DOSStub_100a {
  strings:
    $key_100a = { 44 62 [2] 30 7a [2] 77 78 [2] 30 69 [2] 7e 65 [2] 72 6f [2] 65 64 [2] 7e 2a [2] 43 }

  condition:
    any of them
}