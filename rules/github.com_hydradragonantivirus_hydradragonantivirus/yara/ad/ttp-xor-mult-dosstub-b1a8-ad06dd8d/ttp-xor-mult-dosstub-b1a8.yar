rule TTP_XOR_MULT_DOSStub_b1a8 {
  strings:
    $key_b1a8 = { e5 c0 [2] 91 d8 [2] d6 da [2] 91 cb [2] df c7 [2] d3 cd [2] c4 c6 [2] df 88 [2] e2 }

  condition:
    any of them
}