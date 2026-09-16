rule TTP_XOR_MULT_DOSStub_bab9 {
  strings:
    $key_bab9 = { ee d1 [2] 9a c9 [2] dd cb [2] 9a da [2] d4 d6 [2] d8 dc [2] cf d7 [2] d4 99 [2] e9 }

  condition:
    any of them
}