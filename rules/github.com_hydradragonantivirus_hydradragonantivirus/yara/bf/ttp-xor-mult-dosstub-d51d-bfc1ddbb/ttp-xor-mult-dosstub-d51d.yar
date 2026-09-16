rule TTP_XOR_MULT_DOSStub_d51d {
  strings:
    $key_d51d = { 81 75 [2] f5 6d [2] b2 6f [2] f5 7e [2] bb 72 [2] b7 78 [2] a0 73 [2] bb 3d [2] 86 }

  condition:
    any of them
}