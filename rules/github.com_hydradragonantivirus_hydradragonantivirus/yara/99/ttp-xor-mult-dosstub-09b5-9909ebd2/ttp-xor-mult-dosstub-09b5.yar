rule TTP_XOR_MULT_DOSStub_09b5 {
  strings:
    $key_09b5 = { 5d dd [2] 29 c5 [2] 6e c7 [2] 29 d6 [2] 67 da [2] 6b d0 [2] 7c db [2] 67 95 [2] 5a }

  condition:
    any of them
}