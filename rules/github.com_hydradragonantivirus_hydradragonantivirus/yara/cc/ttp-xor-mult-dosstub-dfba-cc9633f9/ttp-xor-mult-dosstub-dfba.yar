rule TTP_XOR_MULT_DOSStub_dfba {
  strings:
    $key_dfba = { 8b d2 [2] ff ca [2] b8 c8 [2] ff d9 [2] b1 d5 [2] bd df [2] aa d4 [2] b1 9a [2] 8c }

  condition:
    any of them
}