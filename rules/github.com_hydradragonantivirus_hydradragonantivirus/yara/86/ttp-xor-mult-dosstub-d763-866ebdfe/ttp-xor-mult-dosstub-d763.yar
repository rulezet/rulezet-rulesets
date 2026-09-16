rule TTP_XOR_MULT_DOSStub_d763 {
  strings:
    $key_d763 = { 83 0b [2] f7 13 [2] b0 11 [2] f7 00 [2] b9 0c [2] b5 06 [2] a2 0d [2] b9 43 [2] 84 }

  condition:
    any of them
}