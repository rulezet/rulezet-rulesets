rule TTP_XOR_MULT_DOSStub_c4b8 {
  strings:
    $key_c4b8 = { 90 d0 [2] e4 c8 [2] a3 ca [2] e4 db [2] aa d7 [2] a6 dd [2] b1 d6 [2] aa 98 [2] 97 }

  condition:
    any of them
}