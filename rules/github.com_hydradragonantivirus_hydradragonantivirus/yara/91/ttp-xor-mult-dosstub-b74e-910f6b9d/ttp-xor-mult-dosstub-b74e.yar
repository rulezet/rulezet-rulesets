rule TTP_XOR_MULT_DOSStub_b74e {
  strings:
    $key_b74e = { e3 26 [2] 97 3e [2] d0 3c [2] 97 2d [2] d9 21 [2] d5 2b [2] c2 20 [2] d9 6e [2] e4 }

  condition:
    any of them
}