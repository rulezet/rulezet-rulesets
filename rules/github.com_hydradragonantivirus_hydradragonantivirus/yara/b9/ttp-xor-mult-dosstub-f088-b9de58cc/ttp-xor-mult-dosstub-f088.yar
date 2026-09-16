rule TTP_XOR_MULT_DOSStub_f088 {
  strings:
    $key_f088 = { a4 e0 [2] d0 f8 [2] 97 fa [2] d0 eb [2] 9e e7 [2] 92 ed [2] 85 e6 [2] 9e a8 [2] a3 }

  condition:
    any of them
}