rule TTP_XOR_MULT_DOSStub_b175 {
  strings:
    $key_b175 = { e5 1d [2] 91 05 [2] d6 07 [2] 91 16 [2] df 1a [2] d3 10 [2] c4 1b [2] df 55 [2] e2 }

  condition:
    any of them
}