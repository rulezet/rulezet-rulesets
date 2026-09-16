rule TTP_XOR_MULT_DOSStub_a5df {
  strings:
    $key_a5df = { f1 b7 [2] 85 af [2] c2 ad [2] 85 bc [2] cb b0 [2] c7 ba [2] d0 b1 [2] cb ff [2] f6 }

  condition:
    any of them
}