rule TTP_XOR_MULT_DOSStub_5385 {
  strings:
    $key_5385 = { 07 ed [2] 73 f5 [2] 34 f7 [2] 73 e6 [2] 3d ea [2] 31 e0 [2] 26 eb [2] 3d a5 [2] 00 }

  condition:
    any of them
}