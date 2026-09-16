rule TTP_XOR_MULT_DOSStub_f917 {
  strings:
    $key_f917 = { ad 7f [2] d9 67 [2] 9e 65 [2] d9 74 [2] 97 78 [2] 9b 72 [2] 8c 79 [2] 97 37 [2] aa }

  condition:
    any of them
}