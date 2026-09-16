rule TTP_XOR_MULT_DOSStub_7a5d {
  strings:
    $key_7a5d = { 2e 35 [2] 5a 2d [2] 1d 2f [2] 5a 3e [2] 14 32 [2] 18 38 [2] 0f 33 [2] 14 7d [2] 29 }

  condition:
    any of them
}