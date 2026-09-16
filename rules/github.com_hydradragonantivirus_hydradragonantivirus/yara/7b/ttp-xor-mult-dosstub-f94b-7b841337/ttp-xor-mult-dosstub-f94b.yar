rule TTP_XOR_MULT_DOSStub_f94b {
  strings:
    $key_f94b = { ad 23 [2] d9 3b [2] 9e 39 [2] d9 28 [2] 97 24 [2] 9b 2e [2] 8c 25 [2] 97 6b [2] aa }

  condition:
    any of them
}