rule TTP_XOR_MULT_DOSStub_8a60 {
  strings:
    $key_8a60 = { de 08 [2] aa 10 [2] ed 12 [2] aa 03 [2] e4 0f [2] e8 05 [2] ff 0e [2] e4 40 [2] d9 }

  condition:
    any of them
}