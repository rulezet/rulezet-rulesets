rule TTP_XOR_MULT_DOSStub_7001 {
  strings:
    $key_7001 = { 24 69 [2] 50 71 [2] 17 73 [2] 50 62 [2] 1e 6e [2] 12 64 [2] 05 6f [2] 1e 21 [2] 23 }

  condition:
    any of them
}