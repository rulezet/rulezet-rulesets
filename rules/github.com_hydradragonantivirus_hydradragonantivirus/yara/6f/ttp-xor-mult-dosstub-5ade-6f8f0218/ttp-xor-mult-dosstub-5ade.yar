rule TTP_XOR_MULT_DOSStub_5ade {
  strings:
    $key_5ade = { 0e b6 [2] 7a ae [2] 3d ac [2] 7a bd [2] 34 b1 [2] 38 bb [2] 2f b0 [2] 34 fe [2] 09 }

  condition:
    any of them
}