rule TTP_XOR_MULT_DOSStub_8a5b {
  strings:
    $key_8a5b = { de 33 [2] aa 2b [2] ed 29 [2] aa 38 [2] e4 34 [2] e8 3e [2] ff 35 [2] e4 7b [2] d9 }

  condition:
    any of them
}