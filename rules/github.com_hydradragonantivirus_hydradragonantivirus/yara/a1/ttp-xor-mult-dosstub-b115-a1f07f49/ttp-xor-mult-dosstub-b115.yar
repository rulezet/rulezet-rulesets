rule TTP_XOR_MULT_DOSStub_b115 {
  strings:
    $key_b115 = { e5 7d [2] 91 65 [2] d6 67 [2] 91 76 [2] df 7a [2] d3 70 [2] c4 7b [2] df 35 [2] e2 }

  condition:
    any of them
}