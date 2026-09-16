rule TTP_XOR_MULT_DOSStub_89de {
  strings:
    $key_89de = { dd b6 [2] a9 ae [2] ee ac [2] a9 bd [2] e7 b1 [2] eb bb [2] fc b0 [2] e7 fe [2] da }

  condition:
    any of them
}