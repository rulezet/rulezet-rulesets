rule TTP_XOR_MULT_DOSStub_eec0 {
  strings:
    $key_eec0 = { ba a8 [2] ce b0 [2] 89 b2 [2] ce a3 [2] 80 af [2] 8c a5 [2] 9b ae [2] 80 e0 [2] bd }

  condition:
    any of them
}