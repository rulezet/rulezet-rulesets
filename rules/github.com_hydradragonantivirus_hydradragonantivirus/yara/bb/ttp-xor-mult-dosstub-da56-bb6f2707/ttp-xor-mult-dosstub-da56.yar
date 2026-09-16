rule TTP_XOR_MULT_DOSStub_da56 {
  strings:
    $key_da56 = { 8e 3e [2] fa 26 [2] bd 24 [2] fa 35 [2] b4 39 [2] b8 33 [2] af 38 [2] b4 76 [2] 89 }

  condition:
    any of them
}