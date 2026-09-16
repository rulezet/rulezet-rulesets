rule TTP_XOR_MULT_DOSStub_d429 {
  strings:
    $key_d429 = { 80 41 [2] f4 59 [2] b3 5b [2] f4 4a [2] ba 46 [2] b6 4c [2] a1 47 [2] ba 09 [2] 87 }

  condition:
    any of them
}