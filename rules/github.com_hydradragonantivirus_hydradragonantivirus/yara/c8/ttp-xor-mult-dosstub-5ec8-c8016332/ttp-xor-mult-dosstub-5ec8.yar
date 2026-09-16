rule TTP_XOR_MULT_DOSStub_5ec8 {
  strings:
    $key_5ec8 = { 0a a0 [2] 7e b8 [2] 39 ba [2] 7e ab [2] 30 a7 [2] 3c ad [2] 2b a6 [2] 30 e8 [2] 0d }

  condition:
    any of them
}