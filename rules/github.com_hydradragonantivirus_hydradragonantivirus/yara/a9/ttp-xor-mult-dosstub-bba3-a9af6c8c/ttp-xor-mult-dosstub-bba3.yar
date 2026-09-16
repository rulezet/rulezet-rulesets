rule TTP_XOR_MULT_DOSStub_bba3 {
  strings:
    $key_bba3 = { ef cb [2] 9b d3 [2] dc d1 [2] 9b c0 [2] d5 cc [2] d9 c6 [2] ce cd [2] d5 83 [2] e8 }

  condition:
    any of them
}