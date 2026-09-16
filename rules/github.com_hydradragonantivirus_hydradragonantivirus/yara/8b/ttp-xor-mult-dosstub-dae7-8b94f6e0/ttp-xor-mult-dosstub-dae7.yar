rule TTP_XOR_MULT_DOSStub_dae7 {
  strings:
    $key_dae7 = { 8e 8f [2] fa 97 [2] bd 95 [2] fa 84 [2] b4 88 [2] b8 82 [2] af 89 [2] b4 c7 [2] 89 }

  condition:
    any of them
}