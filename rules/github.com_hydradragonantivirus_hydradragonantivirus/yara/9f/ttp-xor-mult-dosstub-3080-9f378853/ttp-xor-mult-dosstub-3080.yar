rule TTP_XOR_MULT_DOSStub_3080 {
  strings:
    $key_3080 = { 64 e8 [2] 10 f0 [2] 57 f2 [2] 10 e3 [2] 5e ef [2] 52 e5 [2] 45 ee [2] 5e a0 [2] 63 }

  condition:
    any of them
}