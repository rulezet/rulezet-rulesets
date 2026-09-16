rule TTP_XOR_MULT_DOSStub_dd15 {
  strings:
    $key_dd15 = { 89 7d [2] fd 65 [2] ba 67 [2] fd 76 [2] b3 7a [2] bf 70 [2] a8 7b [2] b3 35 [2] 8e }

  condition:
    any of them
}