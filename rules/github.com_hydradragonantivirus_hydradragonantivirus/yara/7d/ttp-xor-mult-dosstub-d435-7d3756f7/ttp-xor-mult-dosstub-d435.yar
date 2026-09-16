rule TTP_XOR_MULT_DOSStub_d435 {
  strings:
    $key_d435 = { 80 5d [2] f4 45 [2] b3 47 [2] f4 56 [2] ba 5a [2] b6 50 [2] a1 5b [2] ba 15 [2] 87 }

  condition:
    any of them
}