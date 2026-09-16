rule TTP_XOR_MULT_DOSStub_c1df {
  strings:
    $key_c1df = { 95 b7 [2] e1 af [2] a6 ad [2] e1 bc [2] af b0 [2] a3 ba [2] b4 b1 [2] af ff [2] 92 }

  condition:
    any of them
}