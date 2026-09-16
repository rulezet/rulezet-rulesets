rule TTP_XOR_MULT_DOSStub_2388 {
  strings:
    $key_2388 = { 77 e0 [2] 03 f8 [2] 44 fa [2] 03 eb [2] 4d e7 [2] 41 ed [2] 56 e6 [2] 4d a8 [2] 70 }

  condition:
    any of them
}