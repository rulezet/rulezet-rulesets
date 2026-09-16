rule TTP_XOR_MULT_DOSStub_3620 {
  strings:
    $key_3620 = { 62 48 [2] 16 50 [2] 51 52 [2] 16 43 [2] 58 4f [2] 54 45 [2] 43 4e [2] 58 00 [2] 65 }

  condition:
    any of them
}