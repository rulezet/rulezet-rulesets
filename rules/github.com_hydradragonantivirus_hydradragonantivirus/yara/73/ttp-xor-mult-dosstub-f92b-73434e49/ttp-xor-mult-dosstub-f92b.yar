rule TTP_XOR_MULT_DOSStub_f92b {
  strings:
    $key_f92b = { ad 43 [2] d9 5b [2] 9e 59 [2] d9 48 [2] 97 44 [2] 9b 4e [2] 8c 45 [2] 97 0b [2] aa }

  condition:
    any of them
}