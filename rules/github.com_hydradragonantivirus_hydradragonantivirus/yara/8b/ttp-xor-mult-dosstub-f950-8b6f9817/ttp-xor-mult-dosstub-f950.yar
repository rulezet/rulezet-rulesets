rule TTP_XOR_MULT_DOSStub_f950 {
  strings:
    $key_f950 = { ad 38 [2] d9 20 [2] 9e 22 [2] d9 33 [2] 97 3f [2] 9b 35 [2] 8c 3e [2] 97 70 [2] aa }

  condition:
    any of them
}