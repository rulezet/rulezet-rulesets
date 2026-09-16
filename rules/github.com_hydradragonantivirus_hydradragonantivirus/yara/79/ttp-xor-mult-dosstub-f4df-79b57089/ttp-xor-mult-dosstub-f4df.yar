rule TTP_XOR_MULT_DOSStub_f4df {
  strings:
    $key_f4df = { a0 b7 [2] d4 af [2] 93 ad [2] d4 bc [2] 9a b0 [2] 96 ba [2] 81 b1 [2] 9a ff [2] a7 }

  condition:
    any of them
}