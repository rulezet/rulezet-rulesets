rule TTP_XOR_MULT_DOSStub_8a2c {
  strings:
    $key_8a2c = { de 44 [2] aa 5c [2] ed 5e [2] aa 4f [2] e4 43 [2] e8 49 [2] ff 42 [2] e4 0c [2] d9 }

  condition:
    any of them
}