rule TTP_XOR_MULT_DOSStub_dd99 {
  strings:
    $key_dd99 = { 89 f1 [2] fd e9 [2] ba eb [2] fd fa [2] b3 f6 [2] bf fc [2] a8 f7 [2] b3 b9 [2] 8e }

  condition:
    any of them
}