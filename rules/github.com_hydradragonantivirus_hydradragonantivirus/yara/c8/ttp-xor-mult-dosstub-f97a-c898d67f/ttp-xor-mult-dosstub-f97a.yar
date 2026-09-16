rule TTP_XOR_MULT_DOSStub_f97a {
  strings:
    $key_f97a = { ad 12 [2] d9 0a [2] 9e 08 [2] d9 19 [2] 97 15 [2] 9b 1f [2] 8c 14 [2] 97 5a [2] aa }

  condition:
    any of them
}