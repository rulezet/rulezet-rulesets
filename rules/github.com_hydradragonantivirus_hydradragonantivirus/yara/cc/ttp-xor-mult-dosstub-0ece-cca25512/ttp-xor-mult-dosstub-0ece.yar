rule TTP_XOR_MULT_DOSStub_0ece {
  strings:
    $key_0ece = { 5a a6 [2] 2e be [2] 69 bc [2] 2e ad [2] 60 a1 [2] 6c ab [2] 7b a0 [2] 60 ee [2] 5d }

  condition:
    any of them
}