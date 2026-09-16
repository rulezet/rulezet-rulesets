rule TTP_XOR_MULT_DOSStub_f910 {
  strings:
    $key_f910 = { ad 78 [2] d9 60 [2] 9e 62 [2] d9 73 [2] 97 7f [2] 9b 75 [2] 8c 7e [2] 97 30 [2] aa }

  condition:
    any of them
}