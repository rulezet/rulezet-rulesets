rule TTP_XOR_MULT_DOSStub_0080 {
  strings:
    $key_0080 = { 54 e8 [2] 20 f0 [2] 67 f2 [2] 20 e3 [2] 6e ef [2] 62 e5 [2] 75 ee [2] 6e a0 [2] 53 }

  condition:
    any of them
}