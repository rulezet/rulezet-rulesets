rule TTP_XOR_MULT_DOSStub_1176 {
  strings:
    $key_1176 = { 45 1e [2] 31 06 [2] 76 04 [2] 31 15 [2] 7f 19 [2] 73 13 [2] 64 18 [2] 7f 56 [2] 42 }

  condition:
    any of them
}