rule TTP_XOR_MULT_DOSStub_e1df {
  strings:
    $key_e1df = { b5 b7 [2] c1 af [2] 86 ad [2] c1 bc [2] 8f b0 [2] 83 ba [2] 94 b1 [2] 8f ff [2] b2 }

  condition:
    any of them
}