rule TTP_XOR_MULT_DOSStub_28a3 {
  strings:
    $key_28a3 = { 7c cb [2] 08 d3 [2] 4f d1 [2] 08 c0 [2] 46 cc [2] 4a c6 [2] 5d cd [2] 46 83 [2] 7b }

  condition:
    any of them
}