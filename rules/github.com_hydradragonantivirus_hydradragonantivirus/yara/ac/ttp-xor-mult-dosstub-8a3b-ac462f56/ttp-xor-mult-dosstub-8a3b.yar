rule TTP_XOR_MULT_DOSStub_8a3b {
  strings:
    $key_8a3b = { de 53 [2] aa 4b [2] ed 49 [2] aa 58 [2] e4 54 [2] e8 5e [2] ff 55 [2] e4 1b [2] d9 }

  condition:
    any of them
}