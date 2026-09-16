rule TTP_XOR_MULT_DOSStub_b1e8 {
  strings:
    $key_b1e8 = { e5 80 [2] 91 98 [2] d6 9a [2] 91 8b [2] df 87 [2] d3 8d [2] c4 86 [2] df c8 [2] e2 }

  condition:
    any of them
}