rule TTP_XOR_MULT_DOSStub_8a2d {
  strings:
    $key_8a2d = { de 45 [2] aa 5d [2] ed 5f [2] aa 4e [2] e4 42 [2] e8 48 [2] ff 43 [2] e4 0d [2] d9 }

  condition:
    any of them
}