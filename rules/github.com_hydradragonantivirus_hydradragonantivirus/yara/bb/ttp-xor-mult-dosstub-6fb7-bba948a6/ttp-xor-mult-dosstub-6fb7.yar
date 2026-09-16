rule TTP_XOR_MULT_DOSStub_6fb7 {
  strings:
    $key_6fb7 = { 3b df [2] 4f c7 [2] 08 c5 [2] 4f d4 [2] 01 d8 [2] 0d d2 [2] 1a d9 [2] 01 97 [2] 3c }

  condition:
    any of them
}