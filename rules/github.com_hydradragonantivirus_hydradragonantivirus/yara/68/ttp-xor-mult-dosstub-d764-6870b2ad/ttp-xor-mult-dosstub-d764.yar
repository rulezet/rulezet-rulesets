rule TTP_XOR_MULT_DOSStub_d764 {
  strings:
    $key_d764 = { 83 0c [2] f7 14 [2] b0 16 [2] f7 07 [2] b9 0b [2] b5 01 [2] a2 0a [2] b9 44 [2] 84 }

  condition:
    any of them
}