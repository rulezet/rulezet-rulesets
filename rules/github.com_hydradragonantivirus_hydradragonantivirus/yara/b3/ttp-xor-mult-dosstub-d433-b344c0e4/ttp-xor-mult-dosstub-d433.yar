rule TTP_XOR_MULT_DOSStub_d433 {
  strings:
    $key_d433 = { 80 5b [2] f4 43 [2] b3 41 [2] f4 50 [2] ba 5c [2] b6 56 [2] a1 5d [2] ba 13 [2] 87 }

  condition:
    any of them
}