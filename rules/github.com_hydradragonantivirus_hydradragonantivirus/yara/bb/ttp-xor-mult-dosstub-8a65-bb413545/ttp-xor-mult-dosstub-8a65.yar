rule TTP_XOR_MULT_DOSStub_8a65 {
  strings:
    $key_8a65 = { de 0d [2] aa 15 [2] ed 17 [2] aa 06 [2] e4 0a [2] e8 00 [2] ff 0b [2] e4 45 [2] d9 }

  condition:
    any of them
}