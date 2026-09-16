rule TTP_XOR_MULT_DOSStub_f4ad {
  strings:
    $key_f4ad = { a0 c5 [2] d4 dd [2] 93 df [2] d4 ce [2] 9a c2 [2] 96 c8 [2] 81 c3 [2] 9a 8d [2] a7 }

  condition:
    any of them
}