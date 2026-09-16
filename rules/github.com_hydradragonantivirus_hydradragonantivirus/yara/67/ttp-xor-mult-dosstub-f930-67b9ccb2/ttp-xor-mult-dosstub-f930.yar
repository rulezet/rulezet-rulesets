rule TTP_XOR_MULT_DOSStub_f930 {
  strings:
    $key_f930 = { ad 58 [2] d9 40 [2] 9e 42 [2] d9 53 [2] 97 5f [2] 9b 55 [2] 8c 5e [2] 97 10 [2] aa }

  condition:
    any of them
}