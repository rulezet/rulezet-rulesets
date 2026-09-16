rule TTP_XOR_MULT_DOSStub_4ece {
  strings:
    $key_4ece = { 1a a6 [2] 6e be [2] 29 bc [2] 6e ad [2] 20 a1 [2] 2c ab [2] 3b a0 [2] 20 ee [2] 1d }

  condition:
    any of them
}