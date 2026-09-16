rule TTP_XOR_MULT_DOSStub_b72e {
  strings:
    $key_b72e = { e3 46 [2] 97 5e [2] d0 5c [2] 97 4d [2] d9 41 [2] d5 4b [2] c2 40 [2] d9 0e [2] e4 }

  condition:
    any of them
}