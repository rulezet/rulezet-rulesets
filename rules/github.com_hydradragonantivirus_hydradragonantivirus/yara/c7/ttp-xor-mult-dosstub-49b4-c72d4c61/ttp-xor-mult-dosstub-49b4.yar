rule TTP_XOR_MULT_DOSStub_49b4 {
  strings:
    $key_49b4 = { 1d dc [2] 69 c4 [2] 2e c6 [2] 69 d7 [2] 27 db [2] 2b d1 [2] 3c da [2] 27 94 [2] 1a }

  condition:
    any of them
}