rule TTP_XOR_MULT_DOSStub_d726 {
  strings:
    $key_d726 = { 83 4e [2] f7 56 [2] b0 54 [2] f7 45 [2] b9 49 [2] b5 43 [2] a2 48 [2] b9 06 [2] 84 }

  condition:
    any of them
}