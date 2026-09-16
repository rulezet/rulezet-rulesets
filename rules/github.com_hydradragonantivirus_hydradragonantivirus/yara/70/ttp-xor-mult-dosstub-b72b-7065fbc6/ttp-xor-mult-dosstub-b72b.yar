rule TTP_XOR_MULT_DOSStub_b72b {
  strings:
    $key_b72b = { e3 43 [2] 97 5b [2] d0 59 [2] 97 48 [2] d9 44 [2] d5 4e [2] c2 45 [2] d9 0b [2] e4 }

  condition:
    any of them
}