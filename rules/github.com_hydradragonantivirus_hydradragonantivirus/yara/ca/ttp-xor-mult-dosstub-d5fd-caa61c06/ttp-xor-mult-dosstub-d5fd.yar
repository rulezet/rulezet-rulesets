rule TTP_XOR_MULT_DOSStub_d5fd {
  strings:
    $key_d5fd = { 81 95 [2] f5 8d [2] b2 8f [2] f5 9e [2] bb 92 [2] b7 98 [2] a0 93 [2] bb dd [2] 86 }

  condition:
    any of them
}