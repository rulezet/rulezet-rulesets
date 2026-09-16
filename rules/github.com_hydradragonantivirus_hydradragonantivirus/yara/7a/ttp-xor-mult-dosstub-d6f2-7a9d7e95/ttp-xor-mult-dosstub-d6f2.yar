rule TTP_XOR_MULT_DOSStub_d6f2 {
  strings:
    $key_d6f2 = { 82 9a [2] f6 82 [2] b1 80 [2] f6 91 [2] b8 9d [2] b4 97 [2] a3 9c [2] b8 d2 [2] 85 }

  condition:
    any of them
}