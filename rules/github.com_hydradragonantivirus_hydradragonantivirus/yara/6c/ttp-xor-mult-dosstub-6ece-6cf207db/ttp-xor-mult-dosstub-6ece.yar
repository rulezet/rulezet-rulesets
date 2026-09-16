rule TTP_XOR_MULT_DOSStub_6ece {
  strings:
    $key_6ece = { 3a a6 [2] 4e be [2] 09 bc [2] 4e ad [2] 00 a1 [2] 0c ab [2] 1b a0 [2] 00 ee [2] 3d }

  condition:
    any of them
}