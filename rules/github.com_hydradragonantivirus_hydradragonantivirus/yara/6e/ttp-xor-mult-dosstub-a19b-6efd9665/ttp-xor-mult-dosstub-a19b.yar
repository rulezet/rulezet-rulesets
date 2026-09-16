rule TTP_XOR_MULT_DOSStub_a19b {
  strings:
    $key_a19b = { f5 f3 [2] 81 eb [2] c6 e9 [2] 81 f8 [2] cf f4 [2] c3 fe [2] d4 f5 [2] cf bb [2] f2 }

  condition:
    any of them
}