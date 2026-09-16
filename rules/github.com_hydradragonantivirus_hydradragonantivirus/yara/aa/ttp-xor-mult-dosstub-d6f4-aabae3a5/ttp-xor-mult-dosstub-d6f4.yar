rule TTP_XOR_MULT_DOSStub_d6f4 {
  strings:
    $key_d6f4 = { 82 9c [2] f6 84 [2] b1 86 [2] f6 97 [2] b8 9b [2] b4 91 [2] a3 9a [2] b8 d4 [2] 85 }

  condition:
    any of them
}