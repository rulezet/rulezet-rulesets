rule TTP_XOR_MULT_DOSStub_d730 {
  strings:
    $key_d730 = { 83 58 [2] f7 40 [2] b0 42 [2] f7 53 [2] b9 5f [2] b5 55 [2] a2 5e [2] b9 10 [2] 84 }

  condition:
    any of them
}