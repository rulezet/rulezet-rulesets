rule TTP_XOR_MULT_DOSStub_45df {
  strings:
    $key_45df = { 11 b7 [2] 65 af [2] 22 ad [2] 65 bc [2] 2b b0 [2] 27 ba [2] 30 b1 [2] 2b ff [2] 16 }

  condition:
    any of them
}