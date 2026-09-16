rule TTP_XOR_MULT_DOSStub_7bde {
  strings:
    $key_7bde = { 2f b6 [2] 5b ae [2] 1c ac [2] 5b bd [2] 15 b1 [2] 19 bb [2] 0e b0 [2] 15 fe [2] 28 }

  condition:
    any of them
}