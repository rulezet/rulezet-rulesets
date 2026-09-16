rule TTP_XOR_MULT_DOSStub_b71e {
  strings:
    $key_b71e = { e3 76 [2] 97 6e [2] d0 6c [2] 97 7d [2] d9 71 [2] d5 7b [2] c2 70 [2] d9 3e [2] e4 }

  condition:
    any of them
}