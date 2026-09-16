rule TTP_XOR_MULT_DOSStub_d66e {
  strings:
    $key_d66e = { 82 06 [2] f6 1e [2] b1 1c [2] f6 0d [2] b8 01 [2] b4 0b [2] a3 00 [2] b8 4e [2] 85 }

  condition:
    any of them
}