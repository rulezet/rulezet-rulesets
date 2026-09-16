rule TTP_XOR_MULT_DOSStub_d4fa {
  strings:
    $key_d4fa = { 80 92 [2] f4 8a [2] b3 88 [2] f4 99 [2] ba 95 [2] b6 9f [2] a1 94 [2] ba da [2] 87 }

  condition:
    any of them
}