rule TTP_XOR_MULT_DOSStub_8a11 {
  strings:
    $key_8a11 = { de 79 [2] aa 61 [2] ed 63 [2] aa 72 [2] e4 7e [2] e8 74 [2] ff 7f [2] e4 31 [2] d9 }

  condition:
    any of them
}