rule TTP_XOR_MULT_DOSStub_365d {
  strings:
    $key_365d = { 62 35 [2] 16 2d [2] 51 2f [2] 16 3e [2] 58 32 [2] 54 38 [2] 43 33 [2] 58 7d [2] 65 }

  condition:
    any of them
}