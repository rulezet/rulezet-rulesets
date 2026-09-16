rule TTP_XOR_MULT_DOSStub_d65e {
  strings:
    $key_d65e = { 82 36 [2] f6 2e [2] b1 2c [2] f6 3d [2] b8 31 [2] b4 3b [2] a3 30 [2] b8 7e [2] 85 }

  condition:
    any of them
}