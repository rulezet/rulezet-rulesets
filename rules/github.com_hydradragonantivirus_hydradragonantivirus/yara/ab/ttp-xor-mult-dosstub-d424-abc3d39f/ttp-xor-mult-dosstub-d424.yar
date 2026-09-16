rule TTP_XOR_MULT_DOSStub_d424 {
  strings:
    $key_d424 = { 80 4c [2] f4 54 [2] b3 56 [2] f4 47 [2] ba 4b [2] b6 41 [2] a1 4a [2] ba 04 [2] 87 }

  condition:
    any of them
}