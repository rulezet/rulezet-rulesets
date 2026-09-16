rule TTP_XOR_MULT_DOSStub_8a41 {
  strings:
    $key_8a41 = { de 29 [2] aa 31 [2] ed 33 [2] aa 22 [2] e4 2e [2] e8 24 [2] ff 2f [2] e4 61 [2] d9 }

  condition:
    any of them
}