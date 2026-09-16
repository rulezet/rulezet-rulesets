rule TTP_XOR_MULT_DOSStub_b1eb {
  strings:
    $key_b1eb = { e5 83 [2] 91 9b [2] d6 99 [2] 91 88 [2] df 84 [2] d3 8e [2] c4 85 [2] df cb [2] e2 }

  condition:
    any of them
}