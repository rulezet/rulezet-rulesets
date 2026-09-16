rule TTP_XOR_MULT_DOSStub_8a55 {
  strings:
    $key_8a55 = { de 3d [2] aa 25 [2] ed 27 [2] aa 36 [2] e4 3a [2] e8 30 [2] ff 3b [2] e4 75 [2] d9 }

  condition:
    any of them
}