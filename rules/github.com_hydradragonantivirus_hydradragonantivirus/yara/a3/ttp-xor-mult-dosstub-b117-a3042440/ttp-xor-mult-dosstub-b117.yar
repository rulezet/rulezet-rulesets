rule TTP_XOR_MULT_DOSStub_b117 {
  strings:
    $key_b117 = { e5 7f [2] 91 67 [2] d6 65 [2] 91 74 [2] df 78 [2] d3 72 [2] c4 79 [2] df 37 [2] e2 }

  condition:
    any of them
}