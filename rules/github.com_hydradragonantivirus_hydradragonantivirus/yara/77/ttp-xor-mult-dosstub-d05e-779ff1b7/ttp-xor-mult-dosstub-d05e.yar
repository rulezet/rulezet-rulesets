rule TTP_XOR_MULT_DOSStub_d05e {
  strings:
    $key_d05e = { 84 36 [2] f0 2e [2] b7 2c [2] f0 3d [2] be 31 [2] b2 3b [2] a5 30 [2] be 7e [2] 83 }

  condition:
    any of them
}