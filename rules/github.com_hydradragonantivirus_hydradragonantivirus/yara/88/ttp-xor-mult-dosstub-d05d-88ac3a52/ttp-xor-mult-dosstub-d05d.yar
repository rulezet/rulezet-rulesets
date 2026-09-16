rule TTP_XOR_MULT_DOSStub_d05d {
  strings:
    $key_d05d = { 84 35 [2] f0 2d [2] b7 2f [2] f0 3e [2] be 32 [2] b2 38 [2] a5 33 [2] be 7d [2] 83 }

  condition:
    any of them
}