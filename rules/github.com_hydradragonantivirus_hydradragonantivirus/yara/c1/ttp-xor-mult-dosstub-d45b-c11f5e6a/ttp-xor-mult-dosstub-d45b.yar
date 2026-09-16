rule TTP_XOR_MULT_DOSStub_d45b {
  strings:
    $key_d45b = { 80 33 [2] f4 2b [2] b3 29 [2] f4 38 [2] ba 34 [2] b6 3e [2] a1 35 [2] ba 7b [2] 87 }

  condition:
    any of them
}