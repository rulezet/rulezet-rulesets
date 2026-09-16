rule TTP_XOR_MULT_DOSStub_a48d {
  strings:
    $key_a48d = { f0 e5 [2] 84 fd [2] c3 ff [2] 84 ee [2] ca e2 [2] c6 e8 [2] d1 e3 [2] ca ad [2] f7 }

  condition:
    any of them
}