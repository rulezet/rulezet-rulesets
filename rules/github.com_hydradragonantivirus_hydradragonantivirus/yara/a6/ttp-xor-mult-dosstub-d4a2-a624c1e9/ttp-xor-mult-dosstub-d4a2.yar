rule TTP_XOR_MULT_DOSStub_d4a2 {
  strings:
    $key_d4a2 = { 80 ca [2] f4 d2 [2] b3 d0 [2] f4 c1 [2] ba cd [2] b6 c7 [2] a1 cc [2] ba 82 [2] 87 }

  condition:
    any of them
}