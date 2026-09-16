rule TTP_XOR_MULT_DOSStub_8a19 {
  strings:
    $key_8a19 = { de 71 [2] aa 69 [2] ed 6b [2] aa 7a [2] e4 76 [2] e8 7c [2] ff 77 [2] e4 39 [2] d9 }

  condition:
    any of them
}