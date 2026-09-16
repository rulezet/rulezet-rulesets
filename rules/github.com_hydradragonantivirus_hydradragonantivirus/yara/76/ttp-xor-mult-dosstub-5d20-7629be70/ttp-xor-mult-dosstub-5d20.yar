rule TTP_XOR_MULT_DOSStub_5d20 {
  strings:
    $key_5d20 = { 09 48 [2] 7d 50 [2] 3a 52 [2] 7d 43 [2] 33 4f [2] 3f 45 [2] 28 4e [2] 33 00 [2] 0e }

  condition:
    any of them
}