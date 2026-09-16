rule TTP_XOR_MULT_DOSStub_d42b {
  strings:
    $key_d42b = { 80 43 [2] f4 5b [2] b3 59 [2] f4 48 [2] ba 44 [2] b6 4e [2] a1 45 [2] ba 0b [2] 87 }

  condition:
    any of them
}