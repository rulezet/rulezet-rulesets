rule TTP_XOR_MULT_DOSStub_b15e {
  strings:
    $key_b15e = { e5 36 [2] 91 2e [2] d6 2c [2] 91 3d [2] df 31 [2] d3 3b [2] c4 30 [2] df 7e [2] e2 }

  condition:
    any of them
}