rule TTP_XOR_MULT_DOSStub_d71b {
  strings:
    $key_d71b = { 83 73 [2] f7 6b [2] b0 69 [2] f7 78 [2] b9 74 [2] b5 7e [2] a2 75 [2] b9 3b [2] 84 }

  condition:
    any of them
}