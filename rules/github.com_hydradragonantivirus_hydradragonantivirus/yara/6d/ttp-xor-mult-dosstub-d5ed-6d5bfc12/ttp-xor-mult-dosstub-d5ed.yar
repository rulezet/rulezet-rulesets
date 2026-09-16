rule TTP_XOR_MULT_DOSStub_d5ed {
  strings:
    $key_d5ed = { 81 85 [2] f5 9d [2] b2 9f [2] f5 8e [2] bb 82 [2] b7 88 [2] a0 83 [2] bb cd [2] 86 }

  condition:
    any of them
}