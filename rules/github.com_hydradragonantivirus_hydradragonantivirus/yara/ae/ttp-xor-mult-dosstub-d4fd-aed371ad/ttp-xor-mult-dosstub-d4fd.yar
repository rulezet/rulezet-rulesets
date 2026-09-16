rule TTP_XOR_MULT_DOSStub_d4fd {
  strings:
    $key_d4fd = { 80 95 [2] f4 8d [2] b3 8f [2] f4 9e [2] ba 92 [2] b6 98 [2] a1 93 [2] ba dd [2] 87 }

  condition:
    any of them
}