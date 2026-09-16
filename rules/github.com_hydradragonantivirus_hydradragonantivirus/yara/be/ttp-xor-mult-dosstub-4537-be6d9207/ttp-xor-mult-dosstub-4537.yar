rule TTP_XOR_MULT_DOSStub_4537 {
  strings:
    $key_4537 = { 11 5f [2] 65 47 [2] 22 45 [2] 65 54 [2] 2b 58 [2] 27 52 [2] 30 59 [2] 2b 17 [2] 16 }

  condition:
    any of them
}