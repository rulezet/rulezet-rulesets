rule TTP_XOR_MULT_DOSStub_f9e2 {
  strings:
    $key_f9e2 = { ad 8a [2] d9 92 [2] 9e 90 [2] d9 81 [2] 97 8d [2] 9b 87 [2] 8c 8c [2] 97 c2 [2] aa }

  condition:
    any of them
}