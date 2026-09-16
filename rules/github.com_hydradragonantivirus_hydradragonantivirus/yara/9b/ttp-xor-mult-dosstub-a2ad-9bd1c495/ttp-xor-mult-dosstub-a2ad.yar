rule TTP_XOR_MULT_DOSStub_a2ad {
  strings:
    $key_a2ad = { f6 c5 [2] 82 dd [2] c5 df [2] 82 ce [2] cc c2 [2] c0 c8 [2] d7 c3 [2] cc 8d [2] f1 }

  condition:
    any of them
}