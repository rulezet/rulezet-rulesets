rule TTP_XOR_MULT_DOSStub_b62b {
  strings:
    $key_b62b = { e2 43 [2] 96 5b [2] d1 59 [2] 96 48 [2] d8 44 [2] d4 4e [2] c3 45 [2] d8 0b [2] e5 }

  condition:
    any of them
}