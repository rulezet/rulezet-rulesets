rule TTP_XOR_MULT_DOSStub_19b5 {
  strings:
    $key_19b5 = { 4d dd [2] 39 c5 [2] 7e c7 [2] 39 d6 [2] 77 da [2] 7b d0 [2] 6c db [2] 77 95 [2] 4a }

  condition:
    any of them
}