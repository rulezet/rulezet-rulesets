rule TTP_XOR_MULT_DOSStub_b116 {
  strings:
    $key_b116 = { e5 7e [2] 91 66 [2] d6 64 [2] 91 75 [2] df 79 [2] d3 73 [2] c4 78 [2] df 36 [2] e2 }

  condition:
    any of them
}