rule TTP_XOR_MULT_DOSStub_7220 {
  strings:
    $key_7220 = { 26 48 [2] 52 50 [2] 15 52 [2] 52 43 [2] 1c 4f [2] 10 45 [2] 07 4e [2] 1c 00 [2] 21 }

  condition:
    any of them
}