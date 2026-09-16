rule TTP_XOR_MULT_DOSStub_b138 {
  strings:
    $key_b138 = { e5 50 [2] 91 48 [2] d6 4a [2] 91 5b [2] df 57 [2] d3 5d [2] c4 56 [2] df 18 [2] e2 }

  condition:
    any of them
}