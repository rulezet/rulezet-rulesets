rule TTP_XOR_MULT_DOSStub_a19a {
  strings:
    $key_a19a = { f5 f2 [2] 81 ea [2] c6 e8 [2] 81 f9 [2] cf f5 [2] c3 ff [2] d4 f4 [2] cf ba [2] f2 }

  condition:
    any of them
}