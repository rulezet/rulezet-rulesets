rule TTP_XOR_MULT_DOSStub_dac6 {
  strings:
    $key_dac6 = { 8e ae [2] fa b6 [2] bd b4 [2] fa a5 [2] b4 a9 [2] b8 a3 [2] af a8 [2] b4 e6 [2] 89 }

  condition:
    any of them
}