rule TTP_XOR_MULT_DOSStub_8a76 {
  strings:
    $key_8a76 = { de 1e [2] aa 06 [2] ed 04 [2] aa 15 [2] e4 19 [2] e8 13 [2] ff 18 [2] e4 56 [2] d9 }

  condition:
    any of them
}