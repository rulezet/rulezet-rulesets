rule TTP_XOR_MULT_DOSStub_f5a0 {
  strings:
    $key_f5a0 = { a1 c8 [2] d5 d0 [2] 92 d2 [2] d5 c3 [2] 9b cf [2] 97 c5 [2] 80 ce [2] 9b 80 [2] a6 }

  condition:
    any of them
}