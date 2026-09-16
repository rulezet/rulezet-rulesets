rule TTP_XOR_MULT_DOSStub_aca4 {
  strings:
    $key_aca4 = { f8 cc [2] 8c d4 [2] cb d6 [2] 8c c7 [2] c2 cb [2] ce c1 [2] d9 ca [2] c2 84 [2] ff }

  condition:
    any of them
}