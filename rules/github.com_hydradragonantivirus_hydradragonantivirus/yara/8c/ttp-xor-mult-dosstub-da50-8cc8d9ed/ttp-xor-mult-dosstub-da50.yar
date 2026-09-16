rule TTP_XOR_MULT_DOSStub_da50 {
  strings:
    $key_da50 = { 8e 38 [2] fa 20 [2] bd 22 [2] fa 33 [2] b4 3f [2] b8 35 [2] af 3e [2] b4 70 [2] 89 }

  condition:
    any of them
}