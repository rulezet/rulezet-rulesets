rule TTP_XOR_MULT_DOSStub_b7a3 {
  strings:
    $key_b7a3 = { e3 cb [2] 97 d3 [2] d0 d1 [2] 97 c0 [2] d9 cc [2] d5 c6 [2] c2 cd [2] d9 83 [2] e4 }

  condition:
    any of them
}