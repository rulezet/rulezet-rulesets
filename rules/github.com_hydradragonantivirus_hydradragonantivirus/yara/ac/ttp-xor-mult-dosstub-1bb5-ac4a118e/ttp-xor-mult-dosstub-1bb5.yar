rule TTP_XOR_MULT_DOSStub_1bb5 {
  strings:
    $key_1bb5 = { 4f dd [2] 3b c5 [2] 7c c7 [2] 3b d6 [2] 75 da [2] 79 d0 [2] 6e db [2] 75 95 [2] 48 }

  condition:
    any of them
}