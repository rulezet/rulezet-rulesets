rule TTP_XOR_MULT_DOSStub_1ece {
  strings:
    $key_1ece = { 4a a6 [2] 3e be [2] 79 bc [2] 3e ad [2] 70 a1 [2] 7c ab [2] 6b a0 [2] 70 ee [2] 4d }

  condition:
    any of them
}