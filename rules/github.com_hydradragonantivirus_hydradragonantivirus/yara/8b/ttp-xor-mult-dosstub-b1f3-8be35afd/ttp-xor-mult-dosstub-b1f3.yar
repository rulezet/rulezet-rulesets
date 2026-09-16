rule TTP_XOR_MULT_DOSStub_b1f3 {
  strings:
    $key_b1f3 = { e5 9b [2] 91 83 [2] d6 81 [2] 91 90 [2] df 9c [2] d3 96 [2] c4 9d [2] df d3 [2] e2 }

  condition:
    any of them
}