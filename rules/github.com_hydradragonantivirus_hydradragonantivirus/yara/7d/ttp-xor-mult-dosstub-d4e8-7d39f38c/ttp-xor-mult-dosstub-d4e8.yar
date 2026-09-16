rule TTP_XOR_MULT_DOSStub_d4e8 {
  strings:
    $key_d4e8 = { 80 80 [2] f4 98 [2] b3 9a [2] f4 8b [2] ba 87 [2] b6 8d [2] a1 86 [2] ba c8 [2] 87 }

  condition:
    any of them
}