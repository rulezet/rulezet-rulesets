rule TTP_XOR_MULT_DOSStub_a1df {
  strings:
    $key_a1df = { f5 b7 [2] 81 af [2] c6 ad [2] 81 bc [2] cf b0 [2] c3 ba [2] d4 b1 [2] cf ff [2] f2 }

  condition:
    any of them
}