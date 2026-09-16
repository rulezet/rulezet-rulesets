rule TTP_XOR_MULT_DOSStub_dd08 {
  strings:
    $key_dd08 = { 89 60 [2] fd 78 [2] ba 7a [2] fd 6b [2] b3 67 [2] bf 6d [2] a8 66 [2] b3 28 [2] 8e }

  condition:
    any of them
}