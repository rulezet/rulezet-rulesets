rule TTP_XOR_MULT_DOSStub_b16d {
  strings:
    $key_b16d = { e5 05 [2] 91 1d [2] d6 1f [2] 91 0e [2] df 02 [2] d3 08 [2] c4 03 [2] df 4d [2] e2 }

  condition:
    any of them
}