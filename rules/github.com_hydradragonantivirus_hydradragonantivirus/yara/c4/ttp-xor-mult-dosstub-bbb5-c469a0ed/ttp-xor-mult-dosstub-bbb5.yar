rule TTP_XOR_MULT_DOSStub_bbb5 {
  strings:
    $key_bbb5 = { ef dd [2] 9b c5 [2] dc c7 [2] 9b d6 [2] d5 da [2] d9 d0 [2] ce db [2] d5 95 [2] e8 }

  condition:
    any of them
}