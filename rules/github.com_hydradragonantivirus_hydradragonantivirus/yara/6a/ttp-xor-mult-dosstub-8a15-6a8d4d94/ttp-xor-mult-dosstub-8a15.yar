rule TTP_XOR_MULT_DOSStub_8a15 {
  strings:
    $key_8a15 = { de 7d [2] aa 65 [2] ed 67 [2] aa 76 [2] e4 7a [2] e8 70 [2] ff 7b [2] e4 35 [2] d9 }

  condition:
    any of them
}