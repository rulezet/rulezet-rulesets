rule TTP_XOR_MULT_DOSStub_b1df {
  strings:
    $key_b1df = { e5 b7 [2] 91 af [2] d6 ad [2] 91 bc [2] df b0 [2] d3 ba [2] c4 b1 [2] df ff [2] e2 }

  condition:
    any of them
}