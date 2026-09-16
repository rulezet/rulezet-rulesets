rule TTP_XOR_MULT_DOSStub_d766 {
  strings:
    $key_d766 = { 83 0e [2] f7 16 [2] b0 14 [2] f7 05 [2] b9 09 [2] b5 03 [2] a2 08 [2] b9 46 [2] 84 }

  condition:
    any of them
}