rule TTP_XOR_MULT_DOSStub_05b8 {
  strings:
    $key_05b8 = { 51 d0 [2] 25 c8 [2] 62 ca [2] 25 db [2] 6b d7 [2] 67 dd [2] 70 d6 [2] 6b 98 [2] 56 }

  condition:
    any of them
}