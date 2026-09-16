rule TTP_XOR_MULT_DOSStub_b73e {
  strings:
    $key_b73e = { e3 56 [2] 97 4e [2] d0 4c [2] 97 5d [2] d9 51 [2] d5 5b [2] c2 50 [2] d9 1e [2] e4 }

  condition:
    any of them
}