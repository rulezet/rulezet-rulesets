rule TTP_XOR_MULT_DOSStub_c5b8 {
  strings:
    $key_c5b8 = { 91 d0 [2] e5 c8 [2] a2 ca [2] e5 db [2] ab d7 [2] a7 dd [2] b0 d6 [2] ab 98 [2] 96 }

  condition:
    any of them
}