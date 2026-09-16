rule TTP_XOR_MULT_DOSStub_b0a3 {
  strings:
    $key_b0a3 = { e4 cb [2] 90 d3 [2] d7 d1 [2] 90 c0 [2] de cc [2] d2 c6 [2] c5 cd [2] de 83 [2] e3 }

  condition:
    any of them
}