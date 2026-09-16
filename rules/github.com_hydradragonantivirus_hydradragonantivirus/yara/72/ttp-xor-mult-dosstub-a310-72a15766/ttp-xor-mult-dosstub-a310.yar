rule TTP_XOR_MULT_DOSStub_a310 {
  strings:
    $key_a310 = { f7 78 [2] 83 60 [2] c4 62 [2] 83 73 [2] cd 7f [2] c1 75 [2] d6 7e [2] cd 30 [2] f0 }

  condition:
    any of them
}