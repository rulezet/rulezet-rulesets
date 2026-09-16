rule TTP_XOR_MULT_DOSStub_02b8 {
  strings:
    $key_02b8 = { 56 d0 [2] 22 c8 [2] 65 ca [2] 22 db [2] 6c d7 [2] 60 dd [2] 77 d6 [2] 6c 98 [2] 51 }

  condition:
    any of them
}