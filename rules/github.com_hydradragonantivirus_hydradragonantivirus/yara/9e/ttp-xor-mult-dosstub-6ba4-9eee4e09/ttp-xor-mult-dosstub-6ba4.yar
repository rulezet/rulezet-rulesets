rule TTP_XOR_MULT_DOSStub_6ba4 {
  strings:
    $key_6ba4 = { 3f cc [2] 4b d4 [2] 0c d6 [2] 4b c7 [2] 05 cb [2] 09 c1 [2] 1e ca [2] 05 84 [2] 38 }

  condition:
    any of them
}