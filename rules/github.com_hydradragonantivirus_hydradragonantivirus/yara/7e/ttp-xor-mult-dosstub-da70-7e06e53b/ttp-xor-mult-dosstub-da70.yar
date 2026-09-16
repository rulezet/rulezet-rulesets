rule TTP_XOR_MULT_DOSStub_da70 {
  strings:
    $key_da70 = { 8e 18 [2] fa 00 [2] bd 02 [2] fa 13 [2] b4 1f [2] b8 15 [2] af 1e [2] b4 50 [2] 89 }

  condition:
    any of them
}