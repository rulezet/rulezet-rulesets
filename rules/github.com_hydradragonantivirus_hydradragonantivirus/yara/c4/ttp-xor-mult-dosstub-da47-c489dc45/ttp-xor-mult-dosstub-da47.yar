rule TTP_XOR_MULT_DOSStub_da47 {
  strings:
    $key_da47 = { 8e 2f [2] fa 37 [2] bd 35 [2] fa 24 [2] b4 28 [2] b8 22 [2] af 29 [2] b4 67 [2] 89 }

  condition:
    any of them
}