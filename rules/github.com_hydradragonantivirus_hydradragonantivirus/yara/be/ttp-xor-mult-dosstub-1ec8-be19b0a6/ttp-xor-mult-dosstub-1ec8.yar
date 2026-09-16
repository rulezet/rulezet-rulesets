rule TTP_XOR_MULT_DOSStub_1ec8 {
  strings:
    $key_1ec8 = { 4a a0 [2] 3e b8 [2] 79 ba [2] 3e ab [2] 70 a7 [2] 7c ad [2] 6b a6 [2] 70 e8 [2] 4d }

  condition:
    any of them
}