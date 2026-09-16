rule TTP_XOR_MULT_DOSStub_7620 {
  strings:
    $key_7620 = { 22 48 [2] 56 50 [2] 11 52 [2] 56 43 [2] 18 4f [2] 14 45 [2] 03 4e [2] 18 00 [2] 25 }

  condition:
    any of them
}