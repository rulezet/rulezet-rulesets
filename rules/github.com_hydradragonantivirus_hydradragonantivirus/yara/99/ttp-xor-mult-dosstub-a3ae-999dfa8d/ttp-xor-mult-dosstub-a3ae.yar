rule TTP_XOR_MULT_DOSStub_a3ae {
  strings:
    $key_a3ae = { f7 c6 [2] 83 de [2] c4 dc [2] 83 cd [2] cd c1 [2] c1 cb [2] d6 c0 [2] cd 8e [2] f0 }

  condition:
    any of them
}