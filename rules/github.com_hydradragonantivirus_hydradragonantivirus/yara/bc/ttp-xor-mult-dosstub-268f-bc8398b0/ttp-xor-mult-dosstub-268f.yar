rule TTP_XOR_MULT_DOSStub_268f {
  strings:
    $key_268f = { 72 e7 [2] 06 ff [2] 41 fd [2] 06 ec [2] 48 e0 [2] 44 ea [2] 53 e1 [2] 48 af [2] 75 }

  condition:
    any of them
}