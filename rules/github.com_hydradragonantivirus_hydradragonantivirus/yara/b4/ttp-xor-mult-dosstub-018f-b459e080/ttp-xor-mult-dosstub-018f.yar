rule TTP_XOR_MULT_DOSStub_018f {
  strings:
    $key_018f = { 55 e7 [2] 21 ff [2] 66 fd [2] 21 ec [2] 6f e0 [2] 63 ea [2] 74 e1 [2] 6f af [2] 52 }

  condition:
    any of them
}