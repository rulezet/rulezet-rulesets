rule TTP_XOR_MULT_DOSStub_baa3 {
  strings:
    $key_baa3 = { ee cb [2] 9a d3 [2] dd d1 [2] 9a c0 [2] d4 cc [2] d8 c6 [2] cf cd [2] d4 83 [2] e9 }

  condition:
    any of them
}