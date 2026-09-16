rule TTP_XOR_MULT_DOSStub_3bde {
  strings:
    $key_3bde = { 6f b6 [2] 1b ae [2] 5c ac [2] 1b bd [2] 55 b1 [2] 59 bb [2] 4e b0 [2] 55 fe [2] 68 }

  condition:
    any of them
}