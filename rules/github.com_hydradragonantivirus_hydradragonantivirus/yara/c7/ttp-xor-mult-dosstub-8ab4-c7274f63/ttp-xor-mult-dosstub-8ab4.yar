rule TTP_XOR_MULT_DOSStub_8ab4 {
  strings:
    $key_8ab4 = { de dc [2] aa c4 [2] ed c6 [2] aa d7 [2] e4 db [2] e8 d1 [2] ff da [2] e4 94 [2] d9 }

  condition:
    any of them
}