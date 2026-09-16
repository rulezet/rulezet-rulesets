rule TTP_XOR_MULT_DOSStub_49a2 {
  strings:
    $key_49a2 = { 1d ca [2] 69 d2 [2] 2e d0 [2] 69 c1 [2] 27 cd [2] 2b c7 [2] 3c cc [2] 27 82 [2] 1a }

  condition:
    any of them
}