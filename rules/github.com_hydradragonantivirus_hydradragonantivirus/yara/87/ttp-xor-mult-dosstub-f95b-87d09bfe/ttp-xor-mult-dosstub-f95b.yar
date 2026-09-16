rule TTP_XOR_MULT_DOSStub_f95b {
  strings:
    $key_f95b = { ad 33 [2] d9 2b [2] 9e 29 [2] d9 38 [2] 97 34 [2] 9b 3e [2] 8c 35 [2] 97 7b [2] aa }

  condition:
    any of them
}