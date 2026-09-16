rule TTP_XOR_MULT_DOSStub_d7f9 {
  strings:
    $key_d7f9 = { 83 91 [2] f7 89 [2] b0 8b [2] f7 9a [2] b9 96 [2] b5 9c [2] a2 97 [2] b9 d9 [2] 84 }

  condition:
    any of them
}