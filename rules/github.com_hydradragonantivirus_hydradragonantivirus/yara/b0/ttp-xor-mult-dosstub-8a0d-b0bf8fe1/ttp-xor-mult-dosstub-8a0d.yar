rule TTP_XOR_MULT_DOSStub_8a0d {
  strings:
    $key_8a0d = { de 65 [2] aa 7d [2] ed 7f [2] aa 6e [2] e4 62 [2] e8 68 [2] ff 63 [2] e4 2d [2] d9 }

  condition:
    any of them
}