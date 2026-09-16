rule TTP_XOR_MULT_DOSStub_938f {
  strings:
    $key_938f = { c7 e7 [2] b3 ff [2] f4 fd [2] b3 ec [2] fd e0 [2] f1 ea [2] e6 e1 [2] fd af [2] c0 }

  condition:
    any of them
}