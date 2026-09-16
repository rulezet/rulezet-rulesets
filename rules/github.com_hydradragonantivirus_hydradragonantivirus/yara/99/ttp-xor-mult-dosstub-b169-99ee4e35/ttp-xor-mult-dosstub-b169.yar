rule TTP_XOR_MULT_DOSStub_b169 {
  strings:
    $key_b169 = { e5 01 [2] 91 19 [2] d6 1b [2] 91 0a [2] df 06 [2] d3 0c [2] c4 07 [2] df 49 [2] e2 }

  condition:
    any of them
}