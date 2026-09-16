rule TTP_XOR_MULT_DOSStub_05a0 {
  strings:
    $key_05a0 = { 51 c8 [2] 25 d0 [2] 62 d2 [2] 25 c3 [2] 6b cf [2] 67 c5 [2] 70 ce [2] 6b 80 [2] 56 }

  condition:
    any of them
}