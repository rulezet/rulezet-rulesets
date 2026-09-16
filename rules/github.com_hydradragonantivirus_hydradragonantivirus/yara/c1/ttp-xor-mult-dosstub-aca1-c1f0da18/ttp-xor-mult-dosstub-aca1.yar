rule TTP_XOR_MULT_DOSStub_aca1 {
  strings:
    $key_aca1 = { f8 c9 [2] 8c d1 [2] cb d3 [2] 8c c2 [2] c2 ce [2] ce c4 [2] d9 cf [2] c2 81 [2] ff }

  condition:
    any of them
}