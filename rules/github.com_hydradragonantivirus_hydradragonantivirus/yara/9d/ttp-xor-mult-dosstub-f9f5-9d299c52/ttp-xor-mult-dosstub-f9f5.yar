rule TTP_XOR_MULT_DOSStub_f9f5 {
  strings:
    $key_f9f5 = { ad 9d [2] d9 85 [2] 9e 87 [2] d9 96 [2] 97 9a [2] 9b 90 [2] 8c 9b [2] 97 d5 [2] aa }

  condition:
    any of them
}