rule TTP_XOR_MULT_DOSStub_8a7b {
  strings:
    $key_8a7b = { de 13 [2] aa 0b [2] ed 09 [2] aa 18 [2] e4 14 [2] e8 1e [2] ff 15 [2] e4 5b [2] d9 }

  condition:
    any of them
}