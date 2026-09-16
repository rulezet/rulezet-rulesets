rule TTP_XOR_MULT_DOSStub_c8bb {
  strings:
    $key_c8bb = { 9c d3 [2] e8 cb [2] af c9 [2] e8 d8 [2] a6 d4 [2] aa de [2] bd d5 [2] a6 9b [2] 9b }

  condition:
    any of them
}