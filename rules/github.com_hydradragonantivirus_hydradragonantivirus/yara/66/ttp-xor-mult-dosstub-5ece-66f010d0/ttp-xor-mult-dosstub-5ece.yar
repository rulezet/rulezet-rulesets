rule TTP_XOR_MULT_DOSStub_5ece {
  strings:
    $key_5ece = { 0a a6 [2] 7e be [2] 39 bc [2] 7e ad [2] 30 a1 [2] 3c ab [2] 2b a0 [2] 30 ee [2] 0d }

  condition:
    any of them
}