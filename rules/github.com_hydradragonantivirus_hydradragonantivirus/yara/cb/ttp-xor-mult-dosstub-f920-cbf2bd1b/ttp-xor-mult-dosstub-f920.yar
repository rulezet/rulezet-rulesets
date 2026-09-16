rule TTP_XOR_MULT_DOSStub_f920 {
  strings:
    $key_f920 = { ad 48 [2] d9 50 [2] 9e 52 [2] d9 43 [2] 97 4f [2] 9b 45 [2] 8c 4e [2] 97 00 [2] aa }

  condition:
    any of them
}