rule TTP_XOR_MULT_DOSStub_e5df {
  strings:
    $key_e5df = { b1 b7 [2] c5 af [2] 82 ad [2] c5 bc [2] 8b b0 [2] 87 ba [2] 90 b1 [2] 8b ff [2] b6 }

  condition:
    any of them
}