rule TTP_XOR_MULT_DOSStub_aba3 {
  strings:
    $key_aba3 = { ff cb [2] 8b d3 [2] cc d1 [2] 8b c0 [2] c5 cc [2] c9 c6 [2] de cd [2] c5 83 [2] f8 }

  condition:
    any of them
}