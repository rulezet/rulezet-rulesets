rule TTP_XOR_MULT_DOSStub_d74d {
  strings:
    $key_d74d = { 83 25 [2] f7 3d [2] b0 3f [2] f7 2e [2] b9 22 [2] b5 28 [2] a2 23 [2] b9 6d [2] 84 }

  condition:
    any of them
}