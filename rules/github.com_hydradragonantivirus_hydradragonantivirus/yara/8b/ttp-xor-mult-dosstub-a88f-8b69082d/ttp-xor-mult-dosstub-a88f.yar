rule TTP_XOR_MULT_DOSStub_a88f {
  strings:
    $key_a88f = { fc e7 [2] 88 ff [2] cf fd [2] 88 ec [2] c6 e0 [2] ca ea [2] dd e1 [2] c6 af [2] fb }

  condition:
    any of them
}