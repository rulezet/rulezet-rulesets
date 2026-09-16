rule TTP_XOR_MULT_DOSStub_ddf7 {
  strings:
    $key_ddf7 = { 89 9f [2] fd 87 [2] ba 85 [2] fd 94 [2] b3 98 [2] bf 92 [2] a8 99 [2] b3 d7 [2] 8e }

  condition:
    any of them
}