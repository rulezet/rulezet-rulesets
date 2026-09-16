rule TTP_XOR_MULT_DOSStub_39b4 {
  strings:
    $key_39b4 = { 6d dc [2] 19 c4 [2] 5e c6 [2] 19 d7 [2] 57 db [2] 5b d1 [2] 4c da [2] 57 94 [2] 6a }

  condition:
    any of them
}