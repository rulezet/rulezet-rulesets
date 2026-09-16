rule TTP_XOR_MULT_DOSStub_d716 {
  strings:
    $key_d716 = { 83 7e [2] f7 66 [2] b0 64 [2] f7 75 [2] b9 79 [2] b5 73 [2] a2 78 [2] b9 36 [2] 84 }

  condition:
    any of them
}