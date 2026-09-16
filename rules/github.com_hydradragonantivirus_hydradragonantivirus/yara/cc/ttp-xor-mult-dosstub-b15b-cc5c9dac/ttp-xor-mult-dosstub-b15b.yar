rule TTP_XOR_MULT_DOSStub_b15b {
  strings:
    $key_b15b = { e5 33 [2] 91 2b [2] d6 29 [2] 91 38 [2] df 34 [2] d3 3e [2] c4 35 [2] df 7b [2] e2 }

  condition:
    any of them
}