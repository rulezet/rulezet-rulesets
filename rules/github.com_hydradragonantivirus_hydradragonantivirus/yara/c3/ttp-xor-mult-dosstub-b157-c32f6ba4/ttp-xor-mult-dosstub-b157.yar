rule TTP_XOR_MULT_DOSStub_b157 {
  strings:
    $key_b157 = { e5 3f [2] 91 27 [2] d6 25 [2] 91 34 [2] df 38 [2] d3 32 [2] c4 39 [2] df 77 [2] e2 }

  condition:
    any of them
}