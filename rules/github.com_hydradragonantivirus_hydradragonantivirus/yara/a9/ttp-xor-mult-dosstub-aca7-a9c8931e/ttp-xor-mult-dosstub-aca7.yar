rule TTP_XOR_MULT_DOSStub_aca7 {
  strings:
    $key_aca7 = { f8 cf [2] 8c d7 [2] cb d5 [2] 8c c4 [2] c2 c8 [2] ce c2 [2] d9 c9 [2] c2 87 [2] ff }

  condition:
    any of them
}