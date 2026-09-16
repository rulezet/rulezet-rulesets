rule TTP_XOR_MULT_DOSStub_8a52 {
  strings:
    $key_8a52 = { de 3a [2] aa 22 [2] ed 20 [2] aa 31 [2] e4 3d [2] e8 37 [2] ff 3c [2] e4 72 [2] d9 }

  condition:
    any of them
}