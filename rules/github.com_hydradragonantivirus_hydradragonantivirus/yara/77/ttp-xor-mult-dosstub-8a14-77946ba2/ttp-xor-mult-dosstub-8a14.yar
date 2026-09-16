rule TTP_XOR_MULT_DOSStub_8a14 {
  strings:
    $key_8a14 = { de 7c [2] aa 64 [2] ed 66 [2] aa 77 [2] e4 7b [2] e8 71 [2] ff 7a [2] e4 34 [2] d9 }

  condition:
    any of them
}