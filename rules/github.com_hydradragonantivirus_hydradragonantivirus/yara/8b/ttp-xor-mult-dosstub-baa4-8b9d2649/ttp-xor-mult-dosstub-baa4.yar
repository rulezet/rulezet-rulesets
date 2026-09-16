rule TTP_XOR_MULT_DOSStub_baa4 {
  strings:
    $key_baa4 = { ee cc [2] 9a d4 [2] dd d6 [2] 9a c7 [2] d4 cb [2] d8 c1 [2] cf ca [2] d4 84 [2] e9 }

  condition:
    any of them
}