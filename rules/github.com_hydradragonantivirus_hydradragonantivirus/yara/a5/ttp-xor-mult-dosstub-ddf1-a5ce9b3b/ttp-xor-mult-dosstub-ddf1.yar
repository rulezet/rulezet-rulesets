rule TTP_XOR_MULT_DOSStub_ddf1 {
  strings:
    $key_ddf1 = { 89 99 [2] fd 81 [2] ba 83 [2] fd 92 [2] b3 9e [2] bf 94 [2] a8 9f [2] b3 d1 [2] 8e }

  condition:
    any of them
}