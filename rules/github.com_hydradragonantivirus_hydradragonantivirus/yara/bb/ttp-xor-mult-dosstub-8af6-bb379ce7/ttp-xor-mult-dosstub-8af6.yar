rule TTP_XOR_MULT_DOSStub_8af6 {
  strings:
    $key_8af6 = { de 9e [2] aa 86 [2] ed 84 [2] aa 95 [2] e4 99 [2] e8 93 [2] ff 98 [2] e4 d6 [2] d9 }

  condition:
    any of them
}