rule TTP_XOR_MULT_DOSStub_f95a {
  strings:
    $key_f95a = { ad 32 [2] d9 2a [2] 9e 28 [2] d9 39 [2] 97 35 [2] 9b 3f [2] 8c 34 [2] 97 7a [2] aa }

  condition:
    any of them
}