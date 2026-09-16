rule TTP_XOR_MULT_DOSStub_0ade {
  strings:
    $key_0ade = { 5e b6 [2] 2a ae [2] 6d ac [2] 2a bd [2] 64 b1 [2] 68 bb [2] 7f b0 [2] 64 fe [2] 59 }

  condition:
    any of them
}