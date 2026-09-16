rule TTP_XOR_MULT_DOSStub_8ae4 {
  strings:
    $key_8ae4 = { de 8c [2] aa 94 [2] ed 96 [2] aa 87 [2] e4 8b [2] e8 81 [2] ff 8a [2] e4 c4 [2] d9 }

  condition:
    any of them
}