rule TTP_XOR_MULT_DOSStub_d52b {
  strings:
    $key_d52b = { 81 43 [2] f5 5b [2] b2 59 [2] f5 48 [2] bb 44 [2] b7 4e [2] a0 45 [2] bb 0b [2] 86 }

  condition:
    any of them
}