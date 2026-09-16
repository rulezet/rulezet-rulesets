rule TTP_XOR_MULT_DOSStub_ce9a {
  strings:
    $key_ce9a = { 9a f2 [2] ee ea [2] a9 e8 [2] ee f9 [2] a0 f5 [2] ac ff [2] bb f4 [2] a0 ba [2] 9d }

  condition:
    any of them
}