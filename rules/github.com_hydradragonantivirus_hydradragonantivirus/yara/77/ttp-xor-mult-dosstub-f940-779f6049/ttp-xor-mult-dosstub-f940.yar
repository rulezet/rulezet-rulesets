rule TTP_XOR_MULT_DOSStub_f940 {
  strings:
    $key_f940 = { ad 28 [2] d9 30 [2] 9e 32 [2] d9 23 [2] 97 2f [2] 9b 25 [2] 8c 2e [2] 97 60 [2] aa }

  condition:
    any of them
}