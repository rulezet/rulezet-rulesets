rule TTP_XOR_MULT_DOSStub_3ba4 {
  strings:
    $key_3ba4 = { 6f cc [2] 1b d4 [2] 5c d6 [2] 1b c7 [2] 55 cb [2] 59 c1 [2] 4e ca [2] 55 84 [2] 68 }

  condition:
    any of them
}