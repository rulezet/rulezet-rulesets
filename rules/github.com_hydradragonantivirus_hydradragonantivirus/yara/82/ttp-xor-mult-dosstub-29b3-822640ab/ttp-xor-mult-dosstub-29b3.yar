rule TTP_XOR_MULT_DOSStub_29b3 {
  strings:
    $key_29b3 = { 7d db [2] 09 c3 [2] 4e c1 [2] 09 d0 [2] 47 dc [2] 4b d6 [2] 5c dd [2] 47 93 [2] 7a }

  condition:
    any of them
}