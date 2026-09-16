rule TTP_XOR_MULT_DOSStub_e74b {
  strings:
    $key_e74b = { b3 23 [2] c7 3b [2] 80 39 [2] c7 28 [2] 89 24 [2] 85 2e [2] 92 25 [2] 89 6b [2] b4 }

  condition:
    any of them
}