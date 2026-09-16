rule TTP_XOR_MULT_DOSStub_7a20 {
  strings:
    $key_7a20 = { 2e 48 [2] 5a 50 [2] 1d 52 [2] 5a 43 [2] 14 4f [2] 18 45 [2] 0f 4e [2] 14 00 [2] 29 }

  condition:
    any of them
}