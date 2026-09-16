rule TTP_XOR_MULT_DOSStub_8a4c {
  strings:
    $key_8a4c = { de 24 [2] aa 3c [2] ed 3e [2] aa 2f [2] e4 23 [2] e8 29 [2] ff 22 [2] e4 6c [2] d9 }

  condition:
    any of them
}