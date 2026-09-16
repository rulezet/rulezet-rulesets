rule TTP_XOR_MULT_DOSStub_f931 {
  strings:
    $key_f931 = { ad 59 [2] d9 41 [2] 9e 43 [2] d9 52 [2] 97 5e [2] 9b 54 [2] 8c 5f [2] 97 11 [2] aa }

  condition:
    any of them
}