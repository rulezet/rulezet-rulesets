rule TTP_XOR_MULT_DOSStub_d65c {
  strings:
    $key_d65c = { 82 34 [2] f6 2c [2] b1 2e [2] f6 3f [2] b8 33 [2] b4 39 [2] a3 32 [2] b8 7c [2] 85 }

  condition:
    any of them
}