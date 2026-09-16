rule TTP_XOR_MULT_DOSStub_f7ad {
  strings:
    $key_f7ad = { a3 c5 [2] d7 dd [2] 90 df [2] d7 ce [2] 99 c2 [2] 95 c8 [2] 82 c3 [2] 99 8d [2] a4 }

  condition:
    any of them
}