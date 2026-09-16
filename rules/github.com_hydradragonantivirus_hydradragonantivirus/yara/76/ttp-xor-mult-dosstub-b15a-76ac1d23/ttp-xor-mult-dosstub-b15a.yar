rule TTP_XOR_MULT_DOSStub_b15a {
  strings:
    $key_b15a = { e5 32 [2] 91 2a [2] d6 28 [2] 91 39 [2] df 35 [2] d3 3f [2] c4 34 [2] df 7a [2] e2 }

  condition:
    any of them
}