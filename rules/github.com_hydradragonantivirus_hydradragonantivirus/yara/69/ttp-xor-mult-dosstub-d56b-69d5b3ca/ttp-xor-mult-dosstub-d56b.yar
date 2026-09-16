rule TTP_XOR_MULT_DOSStub_d56b {
  strings:
    $key_d56b = { 81 03 [2] f5 1b [2] b2 19 [2] f5 08 [2] bb 04 [2] b7 0e [2] a0 05 [2] bb 4b [2] 86 }

  condition:
    any of them
}