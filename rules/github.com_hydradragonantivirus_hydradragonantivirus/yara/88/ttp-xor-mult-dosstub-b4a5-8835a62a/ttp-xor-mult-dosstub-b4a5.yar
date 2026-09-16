rule TTP_XOR_MULT_DOSStub_b4a5 {
  strings:
    $key_b4a5 = { e0 cd [2] 94 d5 [2] d3 d7 [2] 94 c6 [2] da ca [2] d6 c0 [2] c1 cb [2] da 85 [2] e7 }

  condition:
    any of them
}