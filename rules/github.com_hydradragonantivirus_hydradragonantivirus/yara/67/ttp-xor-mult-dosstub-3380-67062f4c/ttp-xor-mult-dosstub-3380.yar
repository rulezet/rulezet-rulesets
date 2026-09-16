rule TTP_XOR_MULT_DOSStub_3380 {
  strings:
    $key_3380 = { 67 e8 [2] 13 f0 [2] 54 f2 [2] 13 e3 [2] 5d ef [2] 51 e5 [2] 46 ee [2] 5d a0 [2] 60 }

  condition:
    any of them
}