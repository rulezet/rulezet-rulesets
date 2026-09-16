rule TTP_XOR_MULT_DOSStub_d700 {
  strings:
    $key_d700 = { 83 68 [2] f7 70 [2] b0 72 [2] f7 63 [2] b9 6f [2] b5 65 [2] a2 6e [2] b9 20 [2] 84 }

  condition:
    any of them
}