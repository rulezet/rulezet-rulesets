rule TTP_XOR_MULT_DOSStub_4001 {
  strings:
    $key_4001 = { 14 69 [2] 60 71 [2] 27 73 [2] 60 62 [2] 2e 6e [2] 22 64 [2] 35 6f [2] 2e 21 [2] 13 }

  condition:
    any of them
}