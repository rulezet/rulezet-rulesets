rule TTP_XOR_MULT_DOSStub_f959 {
  strings:
    $key_f959 = { ad 31 [2] d9 29 [2] 9e 2b [2] d9 3a [2] 97 36 [2] 9b 3c [2] 8c 37 [2] 97 79 [2] aa }

  condition:
    any of them
}