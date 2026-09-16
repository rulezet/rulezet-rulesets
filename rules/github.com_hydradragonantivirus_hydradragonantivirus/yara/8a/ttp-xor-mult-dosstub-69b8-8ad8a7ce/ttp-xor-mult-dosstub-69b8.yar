rule TTP_XOR_MULT_DOSStub_69b8 {
  strings:
    $key_69b8 = { 3d d0 [2] 49 c8 [2] 0e ca [2] 49 db [2] 07 d7 [2] 0b dd [2] 1c d6 [2] 07 98 [2] 3a }

  condition:
    any of them
}