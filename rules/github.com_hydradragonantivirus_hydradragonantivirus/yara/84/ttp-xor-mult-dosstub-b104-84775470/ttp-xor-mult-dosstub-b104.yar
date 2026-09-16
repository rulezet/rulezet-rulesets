rule TTP_XOR_MULT_DOSStub_b104 {
  strings:
    $key_b104 = { e5 6c [2] 91 74 [2] d6 76 [2] 91 67 [2] df 6b [2] d3 61 [2] c4 6a [2] df 24 [2] e2 }

  condition:
    any of them
}