rule TTP_XOR_MULT_DOSStub_b2df {
  strings:
    $key_b2df = { e6 b7 [2] 92 af [2] d5 ad [2] 92 bc [2] dc b0 [2] d0 ba [2] c7 b1 [2] dc ff [2] e1 }

  condition:
    any of them
}