rule TTP_XOR_MULT_DOSStub_09b4 {
  strings:
    $key_09b4 = { 5d dc [2] 29 c4 [2] 6e c6 [2] 29 d7 [2] 67 db [2] 6b d1 [2] 7c da [2] 67 94 [2] 5a }

  condition:
    any of them
}