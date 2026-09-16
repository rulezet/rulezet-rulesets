rule TTP_XOR_MULT_DOSStub_d6f9 {
  strings:
    $key_d6f9 = { 82 91 [2] f6 89 [2] b1 8b [2] f6 9a [2] b8 96 [2] b4 9c [2] a3 97 [2] b8 d9 [2] 85 }

  condition:
    any of them
}