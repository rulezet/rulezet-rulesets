rule TTP_XOR_MULT_DOSStub_7720 {
  strings:
    $key_7720 = { 23 48 [2] 57 50 [2] 10 52 [2] 57 43 [2] 19 4f [2] 15 45 [2] 02 4e [2] 19 00 [2] 24 }

  condition:
    any of them
}