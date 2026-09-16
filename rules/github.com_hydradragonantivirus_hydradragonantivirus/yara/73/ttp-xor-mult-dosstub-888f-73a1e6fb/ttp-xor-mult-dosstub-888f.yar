rule TTP_XOR_MULT_DOSStub_888f {
  strings:
    $key_888f = { dc e7 [2] a8 ff [2] ef fd [2] a8 ec [2] e6 e0 [2] ea ea [2] fd e1 [2] e6 af [2] db }

  condition:
    any of them
}