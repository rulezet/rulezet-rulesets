rule TTP_XOR_MULT_DOSStub_9bde {
  strings:
    $key_9bde = { cf b6 [2] bb ae [2] fc ac [2] bb bd [2] f5 b1 [2] f9 bb [2] ee b0 [2] f5 fe [2] c8 }

  condition:
    any of them
}