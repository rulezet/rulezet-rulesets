rule TTP_XOR_MULT_DOSStub_dd52 {
  strings:
    $key_dd52 = { 89 3a [2] fd 22 [2] ba 20 [2] fd 31 [2] b3 3d [2] bf 37 [2] a8 3c [2] b3 72 [2] 8e }

  condition:
    any of them
}