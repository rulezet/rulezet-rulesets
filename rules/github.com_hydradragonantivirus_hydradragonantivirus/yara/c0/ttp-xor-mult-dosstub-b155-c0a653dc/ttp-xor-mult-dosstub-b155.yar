rule TTP_XOR_MULT_DOSStub_b155 {
  strings:
    $key_b155 = { e5 3d [2] 91 25 [2] d6 27 [2] 91 36 [2] df 3a [2] d3 30 [2] c4 3b [2] df 75 [2] e2 }

  condition:
    any of them
}