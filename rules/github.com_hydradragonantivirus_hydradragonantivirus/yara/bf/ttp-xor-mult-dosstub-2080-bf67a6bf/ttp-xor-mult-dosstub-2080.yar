rule TTP_XOR_MULT_DOSStub_2080 {
  strings:
    $key_2080 = { 74 e8 [2] 00 f0 [2] 47 f2 [2] 00 e3 [2] 4e ef [2] 42 e5 [2] 55 ee [2] 4e a0 [2] 73 }

  condition:
    any of them
}