rule TTP_XOR_MULT_DOSStub_bade {
  strings:
    $key_bade = { ee b6 [2] 9a ae [2] dd ac [2] 9a bd [2] d4 b1 [2] d8 bb [2] cf b0 [2] d4 fe [2] e9 }

  condition:
    any of them
}