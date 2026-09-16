rule TTP_XOR_MULT_DOSStub_b1e4 {
  strings:
    $key_b1e4 = { e5 8c [2] 91 94 [2] d6 96 [2] 91 87 [2] df 8b [2] d3 81 [2] c4 8a [2] df c4 [2] e2 }

  condition:
    any of them
}