rule TTP_XOR_MULT_DOSStub_e4b8 {
  strings:
    $key_e4b8 = { b0 d0 [2] c4 c8 [2] 83 ca [2] c4 db [2] 8a d7 [2] 86 dd [2] 91 d6 [2] 8a 98 [2] b7 }

  condition:
    any of them
}