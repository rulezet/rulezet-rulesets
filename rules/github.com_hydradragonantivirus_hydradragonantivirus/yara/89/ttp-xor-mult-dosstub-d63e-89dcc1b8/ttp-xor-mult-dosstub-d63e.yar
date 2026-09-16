rule TTP_XOR_MULT_DOSStub_d63e {
  strings:
    $key_d63e = { 82 56 [2] f6 4e [2] b1 4c [2] f6 5d [2] b8 51 [2] b4 5b [2] a3 50 [2] b8 1e [2] 85 }

  condition:
    any of them
}