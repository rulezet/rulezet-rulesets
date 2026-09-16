rule TTP_XOR_MULT_DOSStub_d62e {
  strings:
    $key_d62e = { 82 46 [2] f6 5e [2] b1 5c [2] f6 4d [2] b8 41 [2] b4 4b [2] a3 40 [2] b8 0e [2] 85 }

  condition:
    any of them
}