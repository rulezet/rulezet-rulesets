rule TTP_XOR_MULT_DOSStub_29b4 {
  strings:
    $key_29b4 = { 7d dc [2] 09 c4 [2] 4e c6 [2] 09 d7 [2] 47 db [2] 4b d1 [2] 5c da [2] 47 94 [2] 7a }

  condition:
    any of them
}