rule TTP_XOR_MULT_DOSStub_8af9 {
  strings:
    $key_8af9 = { de 91 [2] aa 89 [2] ed 8b [2] aa 9a [2] e4 96 [2] e8 9c [2] ff 97 [2] e4 d9 [2] d9 }

  condition:
    any of them
}