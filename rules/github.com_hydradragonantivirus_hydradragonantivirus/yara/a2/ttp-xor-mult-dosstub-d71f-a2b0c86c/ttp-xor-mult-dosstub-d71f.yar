rule TTP_XOR_MULT_DOSStub_d71f {
  strings:
    $key_d71f = { 83 77 [2] f7 6f [2] b0 6d [2] f7 7c [2] b9 70 [2] b5 7a [2] a2 71 [2] b9 3f [2] 84 }

  condition:
    any of them
}