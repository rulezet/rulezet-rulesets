rule TTP_XOR_MULT_DOSStub_2d20 {
  strings:
    $key_2d20 = { 79 48 [2] 0d 50 [2] 4a 52 [2] 0d 43 [2] 43 4f [2] 4f 45 [2] 58 4e [2] 43 00 [2] 7e }

  condition:
    any of them
}