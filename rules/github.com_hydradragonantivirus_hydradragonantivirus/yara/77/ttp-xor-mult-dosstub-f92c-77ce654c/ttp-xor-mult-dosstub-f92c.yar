rule TTP_XOR_MULT_DOSStub_f92c {
  strings:
    $key_f92c = { ad 44 [2] d9 5c [2] 9e 5e [2] d9 4f [2] 97 43 [2] 9b 49 [2] 8c 42 [2] 97 0c [2] aa }

  condition:
    any of them
}