rule TTP_XOR_MULT_DOSStub_dfb7 {
  strings:
    $key_dfb7 = { 8b df [2] ff c7 [2] b8 c5 [2] ff d4 [2] b1 d8 [2] bd d2 [2] aa d9 [2] b1 97 [2] 8c }

  condition:
    any of them
}