rule TTP_XOR_MULT_DOSStub_9b9b {
  strings:
    $key_9b9b = { cf f3 [2] bb eb [2] fc e9 [2] bb f8 [2] f5 f4 [2] f9 fe [2] ee f5 [2] f5 bb [2] c8 }

  condition:
    any of them
}