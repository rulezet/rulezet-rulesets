rule TTP_XOR_MULT_DOSStub_dd56 {
  strings:
    $key_dd56 = { 89 3e [2] fd 26 [2] ba 24 [2] fd 35 [2] b3 39 [2] bf 33 [2] a8 38 [2] b3 76 [2] 8e }

  condition:
    any of them
}