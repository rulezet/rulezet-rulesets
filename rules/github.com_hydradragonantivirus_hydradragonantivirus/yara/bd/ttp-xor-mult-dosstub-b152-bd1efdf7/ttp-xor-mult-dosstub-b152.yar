rule TTP_XOR_MULT_DOSStub_b152 {
  strings:
    $key_b152 = { e5 3a [2] 91 22 [2] d6 20 [2] 91 31 [2] df 3d [2] d3 37 [2] c4 3c [2] df 72 [2] e2 }

  condition:
    any of them
}