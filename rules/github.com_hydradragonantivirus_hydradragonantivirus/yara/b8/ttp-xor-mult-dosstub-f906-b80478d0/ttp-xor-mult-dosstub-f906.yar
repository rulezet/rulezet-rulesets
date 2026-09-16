rule TTP_XOR_MULT_DOSStub_f906 {
  strings:
    $key_f906 = { ad 6e [2] d9 76 [2] 9e 74 [2] d9 65 [2] 97 69 [2] 9b 63 [2] 8c 68 [2] 97 26 [2] aa }

  condition:
    any of them
}