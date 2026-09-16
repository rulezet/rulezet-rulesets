rule TTP_XOR_MULT_DOSStub_a89e {
  strings:
    $key_a89e = { fc f6 [2] 88 ee [2] cf ec [2] 88 fd [2] c6 f1 [2] ca fb [2] dd f0 [2] c6 be [2] fb }

  condition:
    any of them
}