rule TTP_XOR_MULT_DOSStub_b15c {
  strings:
    $key_b15c = { e5 34 [2] 91 2c [2] d6 2e [2] 91 3f [2] df 33 [2] d3 39 [2] c4 32 [2] df 7c [2] e2 }

  condition:
    any of them
}