rule TTP_XOR_MULT_DOSStub_ad8f {
  strings:
    $key_ad8f = { f9 e7 [2] 8d ff [2] ca fd [2] 8d ec [2] c3 e0 [2] cf ea [2] d8 e1 [2] c3 af [2] fe }

  condition:
    any of them
}