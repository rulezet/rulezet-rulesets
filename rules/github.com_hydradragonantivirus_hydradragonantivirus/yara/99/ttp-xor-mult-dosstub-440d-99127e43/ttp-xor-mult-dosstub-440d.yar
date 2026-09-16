rule TTP_XOR_MULT_DOSStub_440d {
  strings:
    $key_440d = { 10 65 [2] 64 7d [2] 23 7f [2] 64 6e [2] 2a 62 [2] 26 68 [2] 31 63 [2] 2a 2d [2] 17 }

  condition:
    any of them
}