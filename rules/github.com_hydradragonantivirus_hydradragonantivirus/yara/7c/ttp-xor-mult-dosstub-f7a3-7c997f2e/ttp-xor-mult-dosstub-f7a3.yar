rule TTP_XOR_MULT_DOSStub_f7a3 {
  strings:
    $key_f7a3 = { a3 cb [2] d7 d3 [2] 90 d1 [2] d7 c0 [2] 99 cc [2] 95 c6 [2] 82 cd [2] 99 83 [2] a4 }

  condition:
    any of them
}