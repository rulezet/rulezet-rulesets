rule TTP_XOR_MULT_DOSStub_38b8 {
  strings:
    $key_38b8 = { 6c d0 [2] 18 c8 [2] 5f ca [2] 18 db [2] 56 d7 [2] 5a dd [2] 4d d6 [2] 56 98 [2] 6b }

  condition:
    any of them
}