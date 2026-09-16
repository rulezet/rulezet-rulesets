rule TTP_XOR_MULT_DOSStub_b135 {
  strings:
    $key_b135 = { e5 5d [2] 91 45 [2] d6 47 [2] 91 56 [2] df 5a [2] d3 50 [2] c4 5b [2] df 15 [2] e2 }

  condition:
    any of them
}