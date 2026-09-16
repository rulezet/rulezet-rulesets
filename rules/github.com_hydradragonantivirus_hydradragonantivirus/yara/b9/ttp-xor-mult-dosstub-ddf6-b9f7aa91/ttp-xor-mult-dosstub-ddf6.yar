rule TTP_XOR_MULT_DOSStub_ddf6 {
  strings:
    $key_ddf6 = { 89 9e [2] fd 86 [2] ba 84 [2] fd 95 [2] b3 99 [2] bf 93 [2] a8 98 [2] b3 d6 [2] 8e }

  condition:
    any of them
}