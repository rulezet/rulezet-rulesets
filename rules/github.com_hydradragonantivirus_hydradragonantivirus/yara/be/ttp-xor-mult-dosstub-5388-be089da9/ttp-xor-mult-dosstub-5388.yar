rule TTP_XOR_MULT_DOSStub_5388 {
  strings:
    $key_5388 = { 07 e0 [2] 73 f8 [2] 34 fa [2] 73 eb [2] 3d e7 [2] 31 ed [2] 26 e6 [2] 3d a8 [2] 00 }

  condition:
    any of them
}