rule TTP_XOR_MULT_DOSStub_dd44 {
  strings:
    $key_dd44 = { 89 2c [2] fd 34 [2] ba 36 [2] fd 27 [2] b3 2b [2] bf 21 [2] a8 2a [2] b3 64 [2] 8e }

  condition:
    any of them
}