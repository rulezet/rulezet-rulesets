rule TTP_XOR_MULT_DOSStub_1020 {
  strings:
    $key_1020 = { 44 48 [2] 30 50 [2] 77 52 [2] 30 43 [2] 7e 4f [2] 72 45 [2] 65 4e [2] 7e 00 [2] 43 }

  condition:
    any of them
}