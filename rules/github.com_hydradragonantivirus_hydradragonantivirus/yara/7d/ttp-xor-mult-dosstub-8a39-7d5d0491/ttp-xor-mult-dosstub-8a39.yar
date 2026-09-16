rule TTP_XOR_MULT_DOSStub_8a39 {
  strings:
    $key_8a39 = { de 51 [2] aa 49 [2] ed 4b [2] aa 5a [2] e4 56 [2] e8 5c [2] ff 57 [2] e4 19 [2] d9 }

  condition:
    any of them
}