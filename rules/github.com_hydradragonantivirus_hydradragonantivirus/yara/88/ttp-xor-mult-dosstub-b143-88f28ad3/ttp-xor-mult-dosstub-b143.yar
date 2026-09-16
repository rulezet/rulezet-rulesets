rule TTP_XOR_MULT_DOSStub_b143 {
  strings:
    $key_b143 = { e5 2b [2] 91 33 [2] d6 31 [2] 91 20 [2] df 2c [2] d3 26 [2] c4 2d [2] df 63 [2] e2 }

  condition:
    any of them
}