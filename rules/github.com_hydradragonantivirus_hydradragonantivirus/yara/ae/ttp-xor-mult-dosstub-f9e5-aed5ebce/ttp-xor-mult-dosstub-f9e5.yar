rule TTP_XOR_MULT_DOSStub_f9e5 {
  strings:
    $key_f9e5 = { ad 8d [2] d9 95 [2] 9e 97 [2] d9 86 [2] 97 8a [2] 9b 80 [2] 8c 8b [2] 97 c5 [2] aa }

  condition:
    any of them
}