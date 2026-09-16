rule TTP_XOR_MULT_DOSStub_b192 {
  strings:
    $key_b192 = { e5 fa [2] 91 e2 [2] d6 e0 [2] 91 f1 [2] df fd [2] d3 f7 [2] c4 fc [2] df b2 [2] e2 }

  condition:
    any of them
}