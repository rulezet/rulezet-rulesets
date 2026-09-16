rule TTP_XOR_MULT_DOSStub_d60e {
  strings:
    $key_d60e = { 82 66 [2] f6 7e [2] b1 7c [2] f6 6d [2] b8 61 [2] b4 6b [2] a3 60 [2] b8 2e [2] 85 }

  condition:
    any of them
}