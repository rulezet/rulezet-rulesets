rule TTP_XOR_MULT_DOSStub_d6e3 {
  strings:
    $key_d6e3 = { 82 8b [2] f6 93 [2] b1 91 [2] f6 80 [2] b8 8c [2] b4 86 [2] a3 8d [2] b8 c3 [2] 85 }

  condition:
    any of them
}