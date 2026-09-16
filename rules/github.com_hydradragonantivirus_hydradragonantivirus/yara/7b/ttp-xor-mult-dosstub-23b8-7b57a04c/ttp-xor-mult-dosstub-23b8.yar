rule TTP_XOR_MULT_DOSStub_23b8 {
  strings:
    $key_23b8 = { 77 d0 [2] 03 c8 [2] 44 ca [2] 03 db [2] 4d d7 [2] 41 dd [2] 56 d6 [2] 4d 98 [2] 70 }

  condition:
    any of them
}