rule TTP_XOR_MULT_DOSStub_b14b {
  strings:
    $key_b14b = { e5 23 [2] 91 3b [2] d6 39 [2] 91 28 [2] df 24 [2] d3 2e [2] c4 25 [2] df 6b [2] e2 }

  condition:
    any of them
}