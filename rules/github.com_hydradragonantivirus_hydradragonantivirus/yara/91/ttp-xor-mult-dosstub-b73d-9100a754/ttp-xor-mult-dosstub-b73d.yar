rule TTP_XOR_MULT_DOSStub_b73d {
  strings:
    $key_b73d = { e3 55 [2] 97 4d [2] d0 4f [2] 97 5e [2] d9 52 [2] d5 58 [2] c2 53 [2] d9 1d [2] e4 }

  condition:
    any of them
}