rule TTP_XOR_MULT_DOSStub_6420 {
  strings:
    $key_6420 = { 30 48 [2] 44 50 [2] 03 52 [2] 44 43 [2] 0a 4f [2] 06 45 [2] 11 4e [2] 0a 00 [2] 37 }

  condition:
    any of them
}