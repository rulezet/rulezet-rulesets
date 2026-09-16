rule TTP_XOR_MULT_DOSStub_4476 {
  strings:
    $key_4476 = { 10 1e [2] 64 06 [2] 23 04 [2] 64 15 [2] 2a 19 [2] 26 13 [2] 31 18 [2] 2a 56 [2] 17 }

  condition:
    any of them
}