rule TTP_XOR_MULT_DOSStub_d891 {
  strings:
    $key_d891 = { 8c f9 [2] f8 e1 [2] bf e3 [2] f8 f2 [2] b6 fe [2] ba f4 [2] ad ff [2] b6 b1 [2] 8b }

  condition:
    any of them
}