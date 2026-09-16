rule TTP_XOR_MULT_DOSStub_6440 {
  strings:
    $key_6440 = { 30 28 [2] 44 30 [2] 03 32 [2] 44 23 [2] 0a 2f [2] 06 25 [2] 11 2e [2] 0a 60 [2] 37 }

  condition:
    any of them
}