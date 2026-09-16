rule TTP_XOR_MULT_DOSStub_1e20 {
  strings:
    $key_1e20 = { 4a 48 [2] 3e 50 [2] 79 52 [2] 3e 43 [2] 70 4f [2] 7c 45 [2] 6b 4e [2] 70 00 [2] 4d }

  condition:
    any of them
}