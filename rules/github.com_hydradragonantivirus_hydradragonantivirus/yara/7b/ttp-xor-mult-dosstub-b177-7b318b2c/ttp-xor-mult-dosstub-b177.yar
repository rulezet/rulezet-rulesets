rule TTP_XOR_MULT_DOSStub_b177 {
  strings:
    $key_b177 = { e5 1f [2] 91 07 [2] d6 05 [2] 91 14 [2] df 18 [2] d3 12 [2] c4 19 [2] df 57 [2] e2 }

  condition:
    any of them
}