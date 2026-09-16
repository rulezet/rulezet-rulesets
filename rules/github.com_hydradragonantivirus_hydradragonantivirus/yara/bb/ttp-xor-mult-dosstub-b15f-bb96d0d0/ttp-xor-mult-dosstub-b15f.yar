rule TTP_XOR_MULT_DOSStub_b15f {
  strings:
    $key_b15f = { e5 37 [2] 91 2f [2] d6 2d [2] 91 3c [2] df 30 [2] d3 3a [2] c4 31 [2] df 7f [2] e2 }

  condition:
    any of them
}