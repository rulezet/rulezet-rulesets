rule TTP_XOR_MULT_DOSStub_dfb6 {
  strings:
    $key_dfb6 = { 8b de [2] ff c6 [2] b8 c4 [2] ff d5 [2] b1 d9 [2] bd d3 [2] aa d8 [2] b1 96 [2] 8c }

  condition:
    any of them
}