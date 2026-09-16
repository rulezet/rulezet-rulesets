rule TTP_XOR_MULT_DOSStub_dd72 {
  strings:
    $key_dd72 = { 89 1a [2] fd 02 [2] ba 00 [2] fd 11 [2] b3 1d [2] bf 17 [2] a8 1c [2] b3 52 [2] 8e }

  condition:
    any of them
}