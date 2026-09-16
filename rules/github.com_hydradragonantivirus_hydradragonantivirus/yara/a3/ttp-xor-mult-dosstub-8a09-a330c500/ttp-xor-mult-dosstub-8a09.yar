rule TTP_XOR_MULT_DOSStub_8a09 {
  strings:
    $key_8a09 = { de 61 [2] aa 79 [2] ed 7b [2] aa 6a [2] e4 66 [2] e8 6c [2] ff 67 [2] e4 29 [2] d9 }

  condition:
    any of them
}