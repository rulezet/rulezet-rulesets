rule TTP_XOR_MULT_DOSStub_2ade {
  strings:
    $key_2ade = { 7e b6 [2] 0a ae [2] 4d ac [2] 0a bd [2] 44 b1 [2] 48 bb [2] 5f b0 [2] 44 fe [2] 79 }

  condition:
    any of them
}