rule TTP_XOR_MULT_DOSStub_a49c {
  strings:
    $key_a49c = { f0 f4 [2] 84 ec [2] c3 ee [2] 84 ff [2] ca f3 [2] c6 f9 [2] d1 f2 [2] ca bc [2] f7 }

  condition:
    any of them
}