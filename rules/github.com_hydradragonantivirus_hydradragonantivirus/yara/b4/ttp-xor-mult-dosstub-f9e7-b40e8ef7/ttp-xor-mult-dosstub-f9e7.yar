rule TTP_XOR_MULT_DOSStub_f9e7 {
  strings:
    $key_f9e7 = { ad 8f [2] d9 97 [2] 9e 95 [2] d9 84 [2] 97 88 [2] 9b 82 [2] 8c 89 [2] 97 c7 [2] aa }

  condition:
    any of them
}