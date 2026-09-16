rule TTP_XOR_MULT_DOSStub_2ec8 {
  strings:
    $key_2ec8 = { 7a a0 [2] 0e b8 [2] 49 ba [2] 0e ab [2] 40 a7 [2] 4c ad [2] 5b a6 [2] 40 e8 [2] 7d }

  condition:
    any of them
}