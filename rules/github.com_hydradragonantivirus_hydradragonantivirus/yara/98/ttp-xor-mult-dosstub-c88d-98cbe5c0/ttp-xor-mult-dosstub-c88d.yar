rule TTP_XOR_MULT_DOSStub_c88d {
  strings:
    $key_c88d = { 9c e5 [2] e8 fd [2] af ff [2] e8 ee [2] a6 e2 [2] aa e8 [2] bd e3 [2] a6 ad [2] 9b }

  condition:
    any of them
}