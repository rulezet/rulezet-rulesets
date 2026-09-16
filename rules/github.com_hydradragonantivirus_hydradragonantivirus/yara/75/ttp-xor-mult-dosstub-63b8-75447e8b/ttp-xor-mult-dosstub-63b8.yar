rule TTP_XOR_MULT_DOSStub_63b8 {
  strings:
    $key_63b8 = { 37 d0 [2] 43 c8 [2] 04 ca [2] 43 db [2] 0d d7 [2] 01 dd [2] 16 d6 [2] 0d 98 [2] 30 }

  condition:
    any of them
}