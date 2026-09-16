rule TTP_XOR_MULT_DOSStub_4bde {
  strings:
    $key_4bde = { 1f b6 [2] 6b ae [2] 2c ac [2] 6b bd [2] 25 b1 [2] 29 bb [2] 3e b0 [2] 25 fe [2] 18 }

  condition:
    any of them
}