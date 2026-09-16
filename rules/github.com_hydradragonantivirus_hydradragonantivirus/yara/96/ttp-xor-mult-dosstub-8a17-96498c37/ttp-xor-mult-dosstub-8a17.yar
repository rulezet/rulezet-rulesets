rule TTP_XOR_MULT_DOSStub_8a17 {
  strings:
    $key_8a17 = { de 7f [2] aa 67 [2] ed 65 [2] aa 74 [2] e4 78 [2] e8 72 [2] ff 79 [2] e4 37 [2] d9 }

  condition:
    any of them
}