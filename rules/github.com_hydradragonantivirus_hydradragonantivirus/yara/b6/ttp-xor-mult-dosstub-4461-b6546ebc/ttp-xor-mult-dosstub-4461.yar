rule TTP_XOR_MULT_DOSStub_4461 {
  strings:
    $key_4461 = { 10 09 [2] 64 11 [2] 23 13 [2] 64 02 [2] 2a 0e [2] 26 04 [2] 31 0f [2] 2a 41 [2] 17 }

  condition:
    any of them
}