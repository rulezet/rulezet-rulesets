rule TTP_XOR_MULT_DOSStub_e14b {
  strings:
    $key_e14b = { b5 23 [2] c1 3b [2] 86 39 [2] c1 28 [2] 8f 24 [2] 83 2e [2] 94 25 [2] 8f 6b [2] b2 }

  condition:
    any of them
}