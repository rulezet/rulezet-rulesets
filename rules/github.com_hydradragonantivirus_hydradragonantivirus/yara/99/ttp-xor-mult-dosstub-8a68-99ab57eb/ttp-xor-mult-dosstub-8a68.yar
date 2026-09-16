rule TTP_XOR_MULT_DOSStub_8a68 {
  strings:
    $key_8a68 = { de 00 [2] aa 18 [2] ed 1a [2] aa 0b [2] e4 07 [2] e8 0d [2] ff 06 [2] e4 48 [2] d9 }

  condition:
    any of them
}