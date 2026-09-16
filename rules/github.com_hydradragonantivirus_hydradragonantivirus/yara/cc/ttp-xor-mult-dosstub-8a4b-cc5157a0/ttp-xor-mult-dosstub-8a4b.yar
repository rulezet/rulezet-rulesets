rule TTP_XOR_MULT_DOSStub_8a4b {
  strings:
    $key_8a4b = { de 23 [2] aa 3b [2] ed 39 [2] aa 28 [2] e4 24 [2] e8 2e [2] ff 25 [2] e4 6b [2] d9 }

  condition:
    any of them
}