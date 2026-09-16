rule TTP_XOR_MULT_DOSStub_6380 {
  strings:
    $key_6380 = { 37 e8 [2] 43 f0 [2] 04 f2 [2] 43 e3 [2] 0d ef [2] 01 e5 [2] 16 ee [2] 0d a0 [2] 30 }

  condition:
    any of them
}