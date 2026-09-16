rule TTP_XOR_MULT_DOSStub_9ade {
  strings:
    $key_9ade = { ce b6 [2] ba ae [2] fd ac [2] ba bd [2] f4 b1 [2] f8 bb [2] ef b0 [2] f4 fe [2] c9 }

  condition:
    any of them
}