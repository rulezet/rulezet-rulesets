rule TTP_XOR_MULT_DOSStub_f905 {
  strings:
    $key_f905 = { ad 6d [2] d9 75 [2] 9e 77 [2] d9 66 [2] 97 6a [2] 9b 60 [2] 8c 6b [2] 97 25 [2] aa }

  condition:
    any of them
}