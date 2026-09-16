rule TTP_XOR_MULT_DOSStub_f5b8 {
  strings:
    $key_f5b8 = { a1 d0 [2] d5 c8 [2] 92 ca [2] d5 db [2] 9b d7 [2] 97 dd [2] 80 d6 [2] 9b 98 [2] a6 }

  condition:
    any of them
}