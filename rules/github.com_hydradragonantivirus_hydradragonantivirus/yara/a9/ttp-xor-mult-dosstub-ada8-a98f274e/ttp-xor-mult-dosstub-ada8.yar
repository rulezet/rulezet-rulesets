rule TTP_XOR_MULT_DOSStub_ada8 {
  strings:
    $key_ada8 = { f9 c0 [2] 8d d8 [2] ca da [2] 8d cb [2] c3 c7 [2] cf cd [2] d8 c6 [2] c3 88 [2] fe }

  condition:
    any of them
}