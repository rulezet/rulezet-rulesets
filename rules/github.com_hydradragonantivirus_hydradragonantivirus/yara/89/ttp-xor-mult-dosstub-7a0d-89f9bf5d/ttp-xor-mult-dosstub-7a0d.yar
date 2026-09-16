rule TTP_XOR_MULT_DOSStub_7a0d {
  strings:
    $key_7a0d = { 2e 65 [2] 5a 7d [2] 1d 7f [2] 5a 6e [2] 14 62 [2] 18 68 [2] 0f 63 [2] 14 2d [2] 29 }

  condition:
    any of them
}