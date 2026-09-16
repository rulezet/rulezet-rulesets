rule TTP_XOR_MULT_DOSStub_d74e {
  strings:
    $key_d74e = { 83 26 [2] f7 3e [2] b0 3c [2] f7 2d [2] b9 21 [2] b5 2b [2] a2 20 [2] b9 6e [2] 84 }

  condition:
    any of them
}