rule TTP_XOR_MULT_DOSStub_ce9e {
  strings:
    $key_ce9e = { 9a f6 [2] ee ee [2] a9 ec [2] ee fd [2] a0 f1 [2] ac fb [2] bb f0 [2] a0 be [2] 9d }

  condition:
    any of them
}