rule TTP_XOR_MULT_DOSStub_8a46 {
  strings:
    $key_8a46 = { de 2e [2] aa 36 [2] ed 34 [2] aa 25 [2] e4 29 [2] e8 23 [2] ff 28 [2] e4 66 [2] d9 }

  condition:
    any of them
}