rule TTP_XOR_MULT_DOSStub_f8bb {
  strings:
    $key_f8bb = { ac d3 [2] d8 cb [2] 9f c9 [2] d8 d8 [2] 96 d4 [2] 9a de [2] 8d d5 [2] 96 9b [2] ab }

  condition:
    any of them
}