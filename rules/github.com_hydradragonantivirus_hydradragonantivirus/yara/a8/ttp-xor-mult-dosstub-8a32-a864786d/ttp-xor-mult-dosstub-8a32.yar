rule TTP_XOR_MULT_DOSStub_8a32 {
  strings:
    $key_8a32 = { de 5a [2] aa 42 [2] ed 40 [2] aa 51 [2] e4 5d [2] e8 57 [2] ff 5c [2] e4 12 [2] d9 }

  condition:
    any of them
}