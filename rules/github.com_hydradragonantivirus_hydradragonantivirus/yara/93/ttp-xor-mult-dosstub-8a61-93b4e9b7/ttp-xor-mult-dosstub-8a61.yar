rule TTP_XOR_MULT_DOSStub_8a61 {
  strings:
    $key_8a61 = { de 09 [2] aa 11 [2] ed 13 [2] aa 02 [2] e4 0e [2] e8 04 [2] ff 0f [2] e4 41 [2] d9 }

  condition:
    any of them
}