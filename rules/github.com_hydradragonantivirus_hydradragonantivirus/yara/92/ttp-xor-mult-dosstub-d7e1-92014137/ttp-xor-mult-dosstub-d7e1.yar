rule TTP_XOR_MULT_DOSStub_d7e1 {
  strings:
    $key_d7e1 = { 83 89 [2] f7 91 [2] b0 93 [2] f7 82 [2] b9 8e [2] b5 84 [2] a2 8f [2] b9 c1 [2] 84 }

  condition:
    any of them
}