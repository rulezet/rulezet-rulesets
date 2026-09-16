rule TTP_XOR_MULT_DOSStub_4d20 {
  strings:
    $key_4d20 = { 19 48 [2] 6d 50 [2] 2a 52 [2] 6d 43 [2] 23 4f [2] 2f 45 [2] 38 4e [2] 23 00 [2] 1e }

  condition:
    any of them
}