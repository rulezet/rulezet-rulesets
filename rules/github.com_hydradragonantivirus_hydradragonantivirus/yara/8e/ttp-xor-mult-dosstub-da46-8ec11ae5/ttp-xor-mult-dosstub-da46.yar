rule TTP_XOR_MULT_DOSStub_da46 {
  strings:
    $key_da46 = { 8e 2e [2] fa 36 [2] bd 34 [2] fa 25 [2] b4 29 [2] b8 23 [2] af 28 [2] b4 66 [2] 89 }

  condition:
    any of them
}