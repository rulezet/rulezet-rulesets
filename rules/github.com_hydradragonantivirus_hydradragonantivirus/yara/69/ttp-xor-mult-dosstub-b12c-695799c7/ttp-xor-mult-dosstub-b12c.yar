rule TTP_XOR_MULT_DOSStub_b12c {
  strings:
    $key_b12c = { e5 44 [2] 91 5c [2] d6 5e [2] 91 4f [2] df 43 [2] d3 49 [2] c4 42 [2] df 0c [2] e2 }

  condition:
    any of them
}