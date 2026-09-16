rule TTP_XOR_MULT_DOSStub_b73a {
  strings:
    $key_b73a = { e3 52 [2] 97 4a [2] d0 48 [2] 97 59 [2] d9 55 [2] d5 5f [2] c2 54 [2] d9 1a [2] e4 }

  condition:
    any of them
}