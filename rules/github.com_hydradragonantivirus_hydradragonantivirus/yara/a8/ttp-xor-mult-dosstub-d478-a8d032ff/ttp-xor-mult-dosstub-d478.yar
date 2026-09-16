rule TTP_XOR_MULT_DOSStub_d478 {
  strings:
    $key_d478 = { 80 10 [2] f4 08 [2] b3 0a [2] f4 1b [2] ba 17 [2] b6 1d [2] a1 16 [2] ba 58 [2] 87 }

  condition:
    any of them
}