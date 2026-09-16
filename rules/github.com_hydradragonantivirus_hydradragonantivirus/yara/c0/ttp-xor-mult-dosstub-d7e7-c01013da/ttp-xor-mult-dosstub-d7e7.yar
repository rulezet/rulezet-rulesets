rule TTP_XOR_MULT_DOSStub_d7e7 {
  strings:
    $key_d7e7 = { 83 8f [2] f7 97 [2] b0 95 [2] f7 84 [2] b9 88 [2] b5 82 [2] a2 89 [2] b9 c7 [2] 84 }

  condition:
    any of them
}