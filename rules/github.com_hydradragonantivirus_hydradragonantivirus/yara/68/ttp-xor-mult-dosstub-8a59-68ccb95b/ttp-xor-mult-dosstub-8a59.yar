rule TTP_XOR_MULT_DOSStub_8a59 {
  strings:
    $key_8a59 = { de 31 [2] aa 29 [2] ed 2b [2] aa 3a [2] e4 36 [2] e8 3c [2] ff 37 [2] e4 79 [2] d9 }

  condition:
    any of them
}