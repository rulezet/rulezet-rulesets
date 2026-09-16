rule TTP_XOR_MULT_DOSStub_8a06 {
  strings:
    $key_8a06 = { de 6e [2] aa 76 [2] ed 74 [2] aa 65 [2] e4 69 [2] e8 63 [2] ff 68 [2] e4 26 [2] d9 }

  condition:
    any of them
}