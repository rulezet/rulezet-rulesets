rule TTP_XOR_MULT_DOSStub_7ade {
  strings:
    $key_7ade = { 2e b6 [2] 5a ae [2] 1d ac [2] 5a bd [2] 14 b1 [2] 18 bb [2] 0f b0 [2] 14 fe [2] 29 }

  condition:
    any of them
}