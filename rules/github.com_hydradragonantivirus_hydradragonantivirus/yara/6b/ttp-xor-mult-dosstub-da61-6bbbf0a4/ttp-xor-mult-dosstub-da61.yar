rule TTP_XOR_MULT_DOSStub_da61 {
  strings:
    $key_da61 = { 8e 09 [2] fa 11 [2] bd 13 [2] fa 02 [2] b4 0e [2] b8 04 [2] af 0f [2] b4 41 [2] 89 }

  condition:
    any of them
}