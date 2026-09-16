rule TTP_XOR_MULT_DOSStub_58b8 {
  strings:
    $key_58b8 = { 0c d0 [2] 78 c8 [2] 3f ca [2] 78 db [2] 36 d7 [2] 3a dd [2] 2d d6 [2] 36 98 [2] 0b }

  condition:
    any of them
}