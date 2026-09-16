rule TTP_XOR_MULT_DOSStub_38a3 {
  strings:
    $key_38a3 = { 6c cb [2] 18 d3 [2] 5f d1 [2] 18 c0 [2] 56 cc [2] 5a c6 [2] 4d cd [2] 56 83 [2] 6b }

  condition:
    any of them
}