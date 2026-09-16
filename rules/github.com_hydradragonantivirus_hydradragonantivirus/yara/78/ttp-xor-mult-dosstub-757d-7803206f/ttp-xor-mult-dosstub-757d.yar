rule TTP_XOR_MULT_DOSStub_757d {
  strings:
    $key_757d = { 21 15 [2] 55 0d [2] 12 0f [2] 55 1e [2] 1b 12 [2] 17 18 [2] 00 13 [2] 1b 5d [2] 26 }

  condition:
    any of them
}