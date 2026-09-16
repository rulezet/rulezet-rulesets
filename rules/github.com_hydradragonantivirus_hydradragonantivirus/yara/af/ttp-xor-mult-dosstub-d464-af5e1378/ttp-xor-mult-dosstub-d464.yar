rule TTP_XOR_MULT_DOSStub_d464 {
  strings:
    $key_d464 = { 80 0c [2] f4 14 [2] b3 16 [2] f4 07 [2] ba 0b [2] b6 01 [2] a1 0a [2] ba 44 [2] 87 }

  condition:
    any of them
}