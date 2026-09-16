rule TTP_XOR_MULT_DOSStub_a19c {
  strings:
    $key_a19c = { f5 f4 [2] 81 ec [2] c6 ee [2] 81 ff [2] cf f3 [2] c3 f9 [2] d4 f2 [2] cf bc [2] f2 }

  condition:
    any of them
}