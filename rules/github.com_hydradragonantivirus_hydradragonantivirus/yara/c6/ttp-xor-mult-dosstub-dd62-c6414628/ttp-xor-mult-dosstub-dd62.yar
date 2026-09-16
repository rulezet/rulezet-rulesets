rule TTP_XOR_MULT_DOSStub_dd62 {
  strings:
    $key_dd62 = { 89 0a [2] fd 12 [2] ba 10 [2] fd 01 [2] b3 0d [2] bf 07 [2] a8 0c [2] b3 42 [2] 8e }

  condition:
    any of them
}