rule TTP_XOR_MULT_DOSStub_b118 {
  strings:
    $key_b118 = { e5 70 [2] 91 68 [2] d6 6a [2] 91 7b [2] df 77 [2] d3 7d [2] c4 76 [2] df 38 [2] e2 }

  condition:
    any of them
}