rule TTP_XOR_MULT_DOSStub_94d5 {
  strings:
    $key_94d5 = { c0 bd [2] b4 a5 [2] f3 a7 [2] b4 b6 [2] fa ba [2] f6 b0 [2] e1 bb [2] fa f5 [2] c7 }

  condition:
    any of them
}