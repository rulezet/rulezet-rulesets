rule TTP_XOR_MULT_DOSStub_c3df {
  strings:
    $key_c3df = { 97 b7 [2] e3 af [2] a4 ad [2] e3 bc [2] ad b0 [2] a1 ba [2] b6 b1 [2] ad ff [2] 90 }

  condition:
    any of them
}