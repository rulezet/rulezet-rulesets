rule TTP_XOR_MULT_DOSStub_b10d {
  strings:
    $key_b10d = { e5 65 [2] 91 7d [2] d6 7f [2] 91 6e [2] df 62 [2] d3 68 [2] c4 63 [2] df 2d [2] e2 }

  condition:
    any of them
}