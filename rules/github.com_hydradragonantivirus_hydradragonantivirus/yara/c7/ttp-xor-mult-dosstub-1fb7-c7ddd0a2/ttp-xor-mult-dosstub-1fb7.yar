rule TTP_XOR_MULT_DOSStub_1fb7 {
  strings:
    $key_1fb7 = { 4b df [2] 3f c7 [2] 78 c5 [2] 3f d4 [2] 71 d8 [2] 7d d2 [2] 6a d9 [2] 71 97 [2] 4c }

  condition:
    any of them
}