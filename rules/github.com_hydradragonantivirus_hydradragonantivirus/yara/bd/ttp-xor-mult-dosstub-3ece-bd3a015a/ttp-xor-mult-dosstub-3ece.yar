rule TTP_XOR_MULT_DOSStub_3ece {
  strings:
    $key_3ece = { 6a a6 [2] 1e be [2] 59 bc [2] 1e ad [2] 50 a1 [2] 5c ab [2] 4b a0 [2] 50 ee [2] 6d }

  condition:
    any of them
}