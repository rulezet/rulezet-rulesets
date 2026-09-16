rule TTP_XOR_MULT_DOSStub_ce9b {
  strings:
    $key_ce9b = { 9a f3 [2] ee eb [2] a9 e9 [2] ee f8 [2] a0 f4 [2] ac fe [2] bb f5 [2] a0 bb [2] 9d }

  condition:
    any of them
}