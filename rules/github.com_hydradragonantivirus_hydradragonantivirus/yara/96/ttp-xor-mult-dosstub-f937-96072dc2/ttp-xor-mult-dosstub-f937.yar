rule TTP_XOR_MULT_DOSStub_f937 {
  strings:
    $key_f937 = { ad 5f [2] d9 47 [2] 9e 45 [2] d9 54 [2] 97 58 [2] 9b 52 [2] 8c 59 [2] 97 17 [2] aa }

  condition:
    any of them
}