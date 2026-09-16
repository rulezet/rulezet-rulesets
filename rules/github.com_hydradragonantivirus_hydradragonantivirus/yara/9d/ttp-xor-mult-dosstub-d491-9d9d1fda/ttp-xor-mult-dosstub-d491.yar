rule TTP_XOR_MULT_DOSStub_d491 {
  strings:
    $key_d491 = { 80 f9 [2] f4 e1 [2] b3 e3 [2] f4 f2 [2] ba fe [2] b6 f4 [2] a1 ff [2] ba b1 [2] 87 }

  condition:
    any of them
}