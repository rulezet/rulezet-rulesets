rule TTP_XOR_MULT_DOSStub_b16e {
  strings:
    $key_b16e = { e5 06 [2] 91 1e [2] d6 1c [2] 91 0d [2] df 01 [2] d3 0b [2] c4 00 [2] df 4e [2] e2 }

  condition:
    any of them
}