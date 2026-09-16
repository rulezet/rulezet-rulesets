rule TTP_XOR_MULT_DOSStub_a88d {
  strings:
    $key_a88d = { fc e5 [2] 88 fd [2] cf ff [2] 88 ee [2] c6 e2 [2] ca e8 [2] dd e3 [2] c6 ad [2] fb }

  condition:
    any of them
}