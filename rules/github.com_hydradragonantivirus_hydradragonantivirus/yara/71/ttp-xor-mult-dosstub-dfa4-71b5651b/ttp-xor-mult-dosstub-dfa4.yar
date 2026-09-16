rule TTP_XOR_MULT_DOSStub_dfa4 {
  strings:
    $key_dfa4 = { 8b cc [2] ff d4 [2] b8 d6 [2] ff c7 [2] b1 cb [2] bd c1 [2] aa ca [2] b1 84 [2] 8c }

  condition:
    any of them
}