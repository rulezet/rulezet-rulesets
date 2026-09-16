rule TTP_XOR_MULT_DOSStub_d633 {
  strings:
    $key_d633 = { 82 5b [2] f6 43 [2] b1 41 [2] f6 50 [2] b8 5c [2] b4 56 [2] a3 5d [2] b8 13 [2] 85 }

  condition:
    any of them
}