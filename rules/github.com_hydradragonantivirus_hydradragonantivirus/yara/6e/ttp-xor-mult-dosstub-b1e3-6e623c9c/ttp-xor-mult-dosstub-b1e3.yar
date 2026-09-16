rule TTP_XOR_MULT_DOSStub_b1e3 {
  strings:
    $key_b1e3 = { e5 8b [2] 91 93 [2] d6 91 [2] 91 80 [2] df 8c [2] d3 86 [2] c4 8d [2] df c3 [2] e2 }

  condition:
    any of them
}