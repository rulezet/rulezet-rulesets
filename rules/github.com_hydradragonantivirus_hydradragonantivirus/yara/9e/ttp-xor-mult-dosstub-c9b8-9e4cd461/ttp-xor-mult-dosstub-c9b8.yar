rule TTP_XOR_MULT_DOSStub_c9b8 {
  strings:
    $key_c9b8 = { 9d d0 [2] e9 c8 [2] ae ca [2] e9 db [2] a7 d7 [2] ab dd [2] bc d6 [2] a7 98 [2] 9a }

  condition:
    any of them
}