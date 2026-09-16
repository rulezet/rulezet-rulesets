rule TTP_XOR_MULT_DOSStub_c28f {
  strings:
    $key_c28f = { 96 e7 [2] e2 ff [2] a5 fd [2] e2 ec [2] ac e0 [2] a0 ea [2] b7 e1 [2] ac af [2] 91 }

  condition:
    any of them
}