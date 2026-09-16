rule TTP_XOR_MULT_DOSStub_26df {
  strings:
    $key_26df = { 72 b7 [2] 06 af [2] 41 ad [2] 06 bc [2] 48 b0 [2] 44 ba [2] 53 b1 [2] 48 ff [2] 75 }

  condition:
    any of them
}