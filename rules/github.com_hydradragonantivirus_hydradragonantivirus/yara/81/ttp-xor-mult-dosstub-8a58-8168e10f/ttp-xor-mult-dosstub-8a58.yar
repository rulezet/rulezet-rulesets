rule TTP_XOR_MULT_DOSStub_8a58 {
  strings:
    $key_8a58 = { de 30 [2] aa 28 [2] ed 2a [2] aa 3b [2] e4 37 [2] e8 3d [2] ff 36 [2] e4 78 [2] d9 }

  condition:
    any of them
}