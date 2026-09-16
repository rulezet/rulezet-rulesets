rule TTP_XOR_MULT_DOSStub_b12e {
  strings:
    $key_b12e = { e5 46 [2] 91 5e [2] d6 5c [2] 91 4d [2] df 41 [2] d3 4b [2] c4 40 [2] df 0e [2] e2 }

  condition:
    any of them
}