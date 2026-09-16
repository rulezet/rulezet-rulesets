rule TTP_XOR_MULT_DOSStub_59b5 {
  strings:
    $key_59b5 = { 0d dd [2] 79 c5 [2] 3e c7 [2] 79 d6 [2] 37 da [2] 3b d0 [2] 2c db [2] 37 95 [2] 0a }

  condition:
    any of them
}