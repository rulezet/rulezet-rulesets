rule TTP_XOR_MULT_DOSStub_b73b {
  strings:
    $key_b73b = { e3 53 [2] 97 4b [2] d0 49 [2] 97 58 [2] d9 54 [2] d5 5e [2] c2 55 [2] d9 1b [2] e4 }

  condition:
    any of them
}