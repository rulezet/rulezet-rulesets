rule TTP_XOR_MULT_DOSStub_f976 {
  strings:
    $key_f976 = { ad 1e [2] d9 06 [2] 9e 04 [2] d9 15 [2] 97 19 [2] 9b 13 [2] 8c 18 [2] 97 56 [2] aa }

  condition:
    any of them
}