rule TTP_XOR_MULT_DOSStub_b14e {
  strings:
    $key_b14e = { e5 26 [2] 91 3e [2] d6 3c [2] 91 2d [2] df 21 [2] d3 2b [2] c4 20 [2] df 6e [2] e2 }

  condition:
    any of them
}