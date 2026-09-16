rule TTP_XOR_MULT_DOSStub_b1e5 {
  strings:
    $key_b1e5 = { e5 8d [2] 91 95 [2] d6 97 [2] 91 86 [2] df 8a [2] d3 80 [2] c4 8b [2] df c5 [2] e2 }

  condition:
    any of them
}