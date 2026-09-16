rule TTP_XOR_MULT_DOSStub_f1ad {
  strings:
    $key_f1ad = { a5 c5 [2] d1 dd [2] 96 df [2] d1 ce [2] 9f c2 [2] 93 c8 [2] 84 c3 [2] 9f 8d [2] a2 }

  condition:
    any of them
}