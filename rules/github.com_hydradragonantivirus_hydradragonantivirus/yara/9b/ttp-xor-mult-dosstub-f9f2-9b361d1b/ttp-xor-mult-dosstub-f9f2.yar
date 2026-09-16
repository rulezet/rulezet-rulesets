rule TTP_XOR_MULT_DOSStub_f9f2 {
  strings:
    $key_f9f2 = { ad 9a [2] d9 82 [2] 9e 80 [2] d9 91 [2] 97 9d [2] 9b 97 [2] 8c 9c [2] 97 d2 [2] aa }

  condition:
    any of them
}