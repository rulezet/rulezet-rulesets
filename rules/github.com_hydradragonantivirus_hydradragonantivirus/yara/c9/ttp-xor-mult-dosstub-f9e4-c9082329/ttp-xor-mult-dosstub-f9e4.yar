rule TTP_XOR_MULT_DOSStub_f9e4 {
  strings:
    $key_f9e4 = { ad 8c [2] d9 94 [2] 9e 96 [2] d9 87 [2] 97 8b [2] 9b 81 [2] 8c 8a [2] 97 c4 [2] aa }

  condition:
    any of them
}