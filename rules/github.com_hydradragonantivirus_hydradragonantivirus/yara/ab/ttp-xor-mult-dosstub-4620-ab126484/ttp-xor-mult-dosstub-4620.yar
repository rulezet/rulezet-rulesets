rule TTP_XOR_MULT_DOSStub_4620 {
  strings:
    $key_4620 = { 12 48 [2] 66 50 [2] 21 52 [2] 66 43 [2] 28 4f [2] 24 45 [2] 33 4e [2] 28 00 [2] 15 }

  condition:
    any of them
}