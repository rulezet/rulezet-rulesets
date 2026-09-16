rule TTP_XOR_MULT_DOSStub_d4fc {
  strings:
    $key_d4fc = { 80 94 [2] f4 8c [2] b3 8e [2] f4 9f [2] ba 93 [2] b6 99 [2] a1 92 [2] ba dc [2] 87 }

  condition:
    any of them
}