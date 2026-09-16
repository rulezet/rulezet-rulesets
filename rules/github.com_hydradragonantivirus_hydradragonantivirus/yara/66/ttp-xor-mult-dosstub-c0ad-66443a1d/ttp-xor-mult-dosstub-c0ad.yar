rule TTP_XOR_MULT_DOSStub_c0ad {
  strings:
    $key_c0ad = { 94 c5 [2] e0 dd [2] a7 df [2] e0 ce [2] ae c2 [2] a2 c8 [2] b5 c3 [2] ae 8d [2] 93 }

  condition:
    any of them
}