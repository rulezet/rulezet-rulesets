rule TTP_XOR_MULT_DOSStub_a3fd {
  strings:
    $key_a3fd = { f7 95 [2] 83 8d [2] c4 8f [2] 83 9e [2] cd 92 [2] c1 98 [2] d6 93 [2] cd dd [2] f0 }

  condition:
    any of them
}