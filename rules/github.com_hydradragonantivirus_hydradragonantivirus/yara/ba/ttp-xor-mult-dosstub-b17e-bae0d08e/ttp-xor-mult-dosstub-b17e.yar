rule TTP_XOR_MULT_DOSStub_b17e {
  strings:
    $key_b17e = { e5 16 [2] 91 0e [2] d6 0c [2] 91 1d [2] df 11 [2] d3 1b [2] c4 10 [2] df 5e [2] e2 }

  condition:
    any of them
}