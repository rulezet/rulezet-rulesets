rule TTP_XOR_MULT_DOSStub_b11f {
  strings:
    $key_b11f = { e5 77 [2] 91 6f [2] d6 6d [2] 91 7c [2] df 70 [2] d3 7a [2] c4 71 [2] df 3f [2] e2 }

  condition:
    any of them
}