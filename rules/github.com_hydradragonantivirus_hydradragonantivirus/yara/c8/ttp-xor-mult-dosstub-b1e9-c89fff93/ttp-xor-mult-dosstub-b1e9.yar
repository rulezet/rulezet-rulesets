rule TTP_XOR_MULT_DOSStub_b1e9 {
  strings:
    $key_b1e9 = { e5 81 [2] 91 99 [2] d6 9b [2] 91 8a [2] df 86 [2] d3 8c [2] c4 87 [2] df c9 [2] e2 }

  condition:
    any of them
}