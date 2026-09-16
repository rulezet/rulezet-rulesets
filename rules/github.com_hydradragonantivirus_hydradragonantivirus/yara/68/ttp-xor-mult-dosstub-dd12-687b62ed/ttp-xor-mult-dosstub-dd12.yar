rule TTP_XOR_MULT_DOSStub_dd12 {
  strings:
    $key_dd12 = { 89 7a [2] fd 62 [2] ba 60 [2] fd 71 [2] b3 7d [2] bf 77 [2] a8 7c [2] b3 32 [2] 8e }

  condition:
    any of them
}