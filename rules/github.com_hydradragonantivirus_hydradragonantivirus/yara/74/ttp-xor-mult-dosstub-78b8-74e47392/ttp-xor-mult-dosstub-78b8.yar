rule TTP_XOR_MULT_DOSStub_78b8 {
  strings:
    $key_78b8 = { 2c d0 [2] 58 c8 [2] 1f ca [2] 58 db [2] 16 d7 [2] 1a dd [2] 0d d6 [2] 16 98 [2] 2b }

  condition:
    any of them
}