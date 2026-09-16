rule TTP_XOR_MULT_DOSStub_46df {
  strings:
    $key_46df = { 12 b7 [2] 66 af [2] 21 ad [2] 66 bc [2] 28 b0 [2] 24 ba [2] 33 b1 [2] 28 ff [2] 15 }

  condition:
    any of them
}