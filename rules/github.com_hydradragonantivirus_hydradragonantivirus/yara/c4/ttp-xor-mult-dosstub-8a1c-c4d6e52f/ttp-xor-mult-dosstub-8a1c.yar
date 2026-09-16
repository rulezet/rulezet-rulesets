rule TTP_XOR_MULT_DOSStub_8a1c {
  strings:
    $key_8a1c = { de 74 [2] aa 6c [2] ed 6e [2] aa 7f [2] e4 73 [2] e8 79 [2] ff 72 [2] e4 3c [2] d9 }

  condition:
    any of them
}