rule TTP_XOR_MULT_DOSStub_dd86 {
  strings:
    $key_dd86 = { 89 ee [2] fd f6 [2] ba f4 [2] fd e5 [2] b3 e9 [2] bf e3 [2] a8 e8 [2] b3 a6 [2] 8e }

  condition:
    any of them
}