rule TTP_XOR_MULT_DOSStub_d422 {
  strings:
    $key_d422 = { 80 4a [2] f4 52 [2] b3 50 [2] f4 41 [2] ba 4d [2] b6 47 [2] a1 4c [2] ba 02 [2] 87 }

  condition:
    any of them
}