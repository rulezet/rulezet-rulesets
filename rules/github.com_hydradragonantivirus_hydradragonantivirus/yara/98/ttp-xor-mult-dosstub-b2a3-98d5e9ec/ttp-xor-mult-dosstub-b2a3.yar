rule TTP_XOR_MULT_DOSStub_b2a3 {
  strings:
    $key_b2a3 = { e6 cb [2] 92 d3 [2] d5 d1 [2] 92 c0 [2] dc cc [2] d0 c6 [2] c7 cd [2] dc 83 [2] e1 }

  condition:
    any of them
}