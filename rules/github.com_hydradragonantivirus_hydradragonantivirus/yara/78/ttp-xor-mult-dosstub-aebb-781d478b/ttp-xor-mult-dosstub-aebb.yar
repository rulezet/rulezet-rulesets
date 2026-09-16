rule TTP_XOR_MULT_DOSStub_aebb {
  strings:
    $key_aebb = { fa d3 [2] 8e cb [2] c9 c9 [2] 8e d8 [2] c0 d4 [2] cc de [2] db d5 [2] c0 9b [2] fd }

  condition:
    any of them
}