rule TTP_XOR_MULT_DOSStub_b124 {
  strings:
    $key_b124 = { e5 4c [2] 91 54 [2] d6 56 [2] 91 47 [2] df 4b [2] d3 41 [2] c4 4a [2] df 04 [2] e2 }

  condition:
    any of them
}