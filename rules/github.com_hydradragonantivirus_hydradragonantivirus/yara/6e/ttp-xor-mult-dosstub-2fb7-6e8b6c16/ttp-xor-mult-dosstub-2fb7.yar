rule TTP_XOR_MULT_DOSStub_2fb7 {
  strings:
    $key_2fb7 = { 7b df [2] 0f c7 [2] 48 c5 [2] 0f d4 [2] 41 d8 [2] 4d d2 [2] 5a d9 [2] 41 97 [2] 7c }

  condition:
    any of them
}