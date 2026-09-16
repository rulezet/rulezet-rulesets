rule TTP_XOR_MULT_DOSStub_f938 {
  strings:
    $key_f938 = { ad 50 [2] d9 48 [2] 9e 4a [2] d9 5b [2] 97 57 [2] 9b 5d [2] 8c 56 [2] 97 18 [2] aa }

  condition:
    any of them
}