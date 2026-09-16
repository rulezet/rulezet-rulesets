rule TTP_XOR_MULT_DOSStub_6080 {
  strings:
    $key_6080 = { 34 e8 [2] 40 f0 [2] 07 f2 [2] 40 e3 [2] 0e ef [2] 02 e5 [2] 15 ee [2] 0e a0 [2] 33 }

  condition:
    any of them
}