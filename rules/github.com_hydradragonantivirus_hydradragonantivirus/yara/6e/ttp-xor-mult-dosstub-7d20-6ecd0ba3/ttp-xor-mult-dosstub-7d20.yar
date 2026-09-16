rule TTP_XOR_MULT_DOSStub_7d20 {
  strings:
    $key_7d20 = { 29 48 [2] 5d 50 [2] 1a 52 [2] 5d 43 [2] 13 4f [2] 1f 45 [2] 08 4e [2] 13 00 [2] 2e }

  condition:
    any of them
}