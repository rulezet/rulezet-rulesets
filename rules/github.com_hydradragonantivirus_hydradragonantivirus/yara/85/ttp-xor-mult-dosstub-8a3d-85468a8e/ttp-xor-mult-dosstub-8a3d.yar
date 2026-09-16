rule TTP_XOR_MULT_DOSStub_8a3d {
  strings:
    $key_8a3d = { de 55 [2] aa 4d [2] ed 4f [2] aa 5e [2] e4 52 [2] e8 58 [2] ff 53 [2] e4 1d [2] d9 }

  condition:
    any of them
}