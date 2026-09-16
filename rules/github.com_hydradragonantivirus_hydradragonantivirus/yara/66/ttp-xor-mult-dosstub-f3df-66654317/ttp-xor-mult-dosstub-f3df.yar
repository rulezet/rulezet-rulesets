rule TTP_XOR_MULT_DOSStub_f3df {
  strings:
    $key_f3df = { a7 b7 [2] d3 af [2] 94 ad [2] d3 bc [2] 9d b0 [2] 91 ba [2] 86 b1 [2] 9d ff [2] a0 }

  condition:
    any of them
}