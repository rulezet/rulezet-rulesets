rule TTP_XOR_MULT_DOSStub_79b5 {
  strings:
    $key_79b5 = { 2d dd [2] 59 c5 [2] 1e c7 [2] 59 d6 [2] 17 da [2] 1b d0 [2] 0c db [2] 17 95 [2] 2a }

  condition:
    any of them
}