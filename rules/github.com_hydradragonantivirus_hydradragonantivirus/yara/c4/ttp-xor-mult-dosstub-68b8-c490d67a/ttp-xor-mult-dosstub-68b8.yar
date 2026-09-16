rule TTP_XOR_MULT_DOSStub_68b8 {
  strings:
    $key_68b8 = { 3c d0 [2] 48 c8 [2] 0f ca [2] 48 db [2] 06 d7 [2] 0a dd [2] 1d d6 [2] 06 98 [2] 3b }

  condition:
    any of them
}