rule TTP_XOR_MULT_DOSStub_f97b {
  strings:
    $key_f97b = { ad 13 [2] d9 0b [2] 9e 09 [2] d9 18 [2] 97 14 [2] 9b 1e [2] 8c 15 [2] 97 5b [2] aa }

  condition:
    any of them
}