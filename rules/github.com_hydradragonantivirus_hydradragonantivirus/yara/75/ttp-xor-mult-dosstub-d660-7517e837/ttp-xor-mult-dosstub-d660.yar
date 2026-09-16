rule TTP_XOR_MULT_DOSStub_d660 {
  strings:
    $key_d660 = { 82 08 [2] f6 10 [2] b1 12 [2] f6 03 [2] b8 0f [2] b4 05 [2] a3 0e [2] b8 40 [2] 85 }

  condition:
    any of them
}