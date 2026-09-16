rule TTP_XOR_MULT_DOSStub_3ec8 {
  strings:
    $key_3ec8 = { 6a a0 [2] 1e b8 [2] 59 ba [2] 1e ab [2] 50 a7 [2] 5c ad [2] 4b a6 [2] 50 e8 [2] 6d }

  condition:
    any of them
}