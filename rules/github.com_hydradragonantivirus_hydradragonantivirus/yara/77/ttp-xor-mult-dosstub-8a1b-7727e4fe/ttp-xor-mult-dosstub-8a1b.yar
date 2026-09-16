rule TTP_XOR_MULT_DOSStub_8a1b {
  strings:
    $key_8a1b = { de 73 [2] aa 6b [2] ed 69 [2] aa 78 [2] e4 74 [2] e8 7e [2] ff 75 [2] e4 3b [2] d9 }

  condition:
    any of them
}