rule TTP_XOR_MULT_DOSStub_b165 {
  strings:
    $key_b165 = { e5 0d [2] 91 15 [2] d6 17 [2] 91 06 [2] df 0a [2] d3 00 [2] c4 0b [2] df 45 [2] e2 }

  condition:
    any of them
}