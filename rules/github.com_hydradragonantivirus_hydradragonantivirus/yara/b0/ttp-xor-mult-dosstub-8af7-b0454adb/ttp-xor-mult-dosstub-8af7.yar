rule TTP_XOR_MULT_DOSStub_8af7 {
  strings:
    $key_8af7 = { de 9f [2] aa 87 [2] ed 85 [2] aa 94 [2] e4 98 [2] e8 92 [2] ff 99 [2] e4 d7 [2] d9 }

  condition:
    any of them
}