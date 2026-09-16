rule TTP_XOR_MULT_DOSStub_a0ad {
  strings:
    $key_a0ad = { f4 c5 [2] 80 dd [2] c7 df [2] 80 ce [2] ce c2 [2] c2 c8 [2] d5 c3 [2] ce 8d [2] f3 }

  condition:
    any of them
}