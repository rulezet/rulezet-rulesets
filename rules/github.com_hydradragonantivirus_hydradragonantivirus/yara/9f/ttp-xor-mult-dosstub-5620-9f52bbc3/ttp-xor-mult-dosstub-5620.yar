rule TTP_XOR_MULT_DOSStub_5620 {
  strings:
    $key_5620 = { 02 48 [2] 76 50 [2] 31 52 [2] 76 43 [2] 38 4f [2] 34 45 [2] 23 4e [2] 38 00 [2] 05 }

  condition:
    any of them
}