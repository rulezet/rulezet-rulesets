rule TTP_XOR_MULT_DOSStub_d636 {
  strings:
    $key_d636 = { 82 5e [2] f6 46 [2] b1 44 [2] f6 55 [2] b8 59 [2] b4 53 [2] a3 58 [2] b8 16 [2] 85 }

  condition:
    any of them
}