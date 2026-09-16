rule TTP_XOR_MULT_DOSStub_76b8 {
  strings:
    $key_76b8 = { 22 d0 [2] 56 c8 [2] 11 ca [2] 56 db [2] 18 d7 [2] 14 dd [2] 03 d6 [2] 18 98 [2] 25 }

  condition:
    any of them
}