rule TTP_XOR_MULT_DOSStub_8a30 {
  strings:
    $key_8a30 = { de 58 [2] aa 40 [2] ed 42 [2] aa 53 [2] e4 5f [2] e8 55 [2] ff 5e [2] e4 10 [2] d9 }

  condition:
    any of them
}