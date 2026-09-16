rule TTP_XOR_MULT_DOSStub_d64c {
  strings:
    $key_d64c = { 82 24 [2] f6 3c [2] b1 3e [2] f6 2f [2] b8 23 [2] b4 29 [2] a3 22 [2] b8 6c [2] 85 }

  condition:
    any of them
}