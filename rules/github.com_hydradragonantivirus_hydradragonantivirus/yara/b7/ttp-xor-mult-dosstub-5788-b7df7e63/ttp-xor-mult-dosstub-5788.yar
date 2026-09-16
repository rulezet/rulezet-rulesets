rule TTP_XOR_MULT_DOSStub_5788 {
  strings:
    $key_5788 = { 03 e0 [2] 77 f8 [2] 30 fa [2] 77 eb [2] 39 e7 [2] 35 ed [2] 22 e6 [2] 39 a8 [2] 04 }

  condition:
    any of them
}