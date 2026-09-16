rule TTP_XOR_MULT_DOSStub_f2a3 {
  strings:
    $key_f2a3 = { a6 cb [2] d2 d3 [2] 95 d1 [2] d2 c0 [2] 9c cc [2] 90 c6 [2] 87 cd [2] 9c 83 [2] a1 }

  condition:
    any of them
}