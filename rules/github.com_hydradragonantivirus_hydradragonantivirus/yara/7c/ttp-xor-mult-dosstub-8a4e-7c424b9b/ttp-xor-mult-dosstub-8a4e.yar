rule TTP_XOR_MULT_DOSStub_8a4e {
  strings:
    $key_8a4e = { de 26 [2] aa 3e [2] ed 3c [2] aa 2d [2] e4 21 [2] e8 2b [2] ff 20 [2] e4 6e [2] d9 }

  condition:
    any of them
}