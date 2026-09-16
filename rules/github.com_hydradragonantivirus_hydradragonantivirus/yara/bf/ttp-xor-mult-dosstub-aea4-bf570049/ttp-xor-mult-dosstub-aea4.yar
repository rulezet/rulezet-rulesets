rule TTP_XOR_MULT_DOSStub_aea4 {
  strings:
    $key_aea4 = { fa cc [2] 8e d4 [2] c9 d6 [2] 8e c7 [2] c0 cb [2] cc c1 [2] db ca [2] c0 84 [2] fd }

  condition:
    any of them
}