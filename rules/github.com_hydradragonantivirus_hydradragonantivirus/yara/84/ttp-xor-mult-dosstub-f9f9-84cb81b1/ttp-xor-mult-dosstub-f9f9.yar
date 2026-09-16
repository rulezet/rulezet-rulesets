rule TTP_XOR_MULT_DOSStub_f9f9 {
  strings:
    $key_f9f9 = { ad 91 [2] d9 89 [2] 9e 8b [2] d9 9a [2] 97 96 [2] 9b 9c [2] 8c 97 [2] 97 d9 [2] aa }

  condition:
    any of them
}