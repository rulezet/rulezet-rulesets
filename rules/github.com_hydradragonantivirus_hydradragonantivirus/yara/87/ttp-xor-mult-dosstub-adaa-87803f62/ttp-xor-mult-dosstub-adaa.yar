rule TTP_XOR_MULT_DOSStub_adaa {
  strings:
    $key_adaa = { f9 c2 [2] 8d da [2] ca d8 [2] 8d c9 [2] c3 c5 [2] cf cf [2] d8 c4 [2] c3 8a [2] fe }

  condition:
    any of them
}