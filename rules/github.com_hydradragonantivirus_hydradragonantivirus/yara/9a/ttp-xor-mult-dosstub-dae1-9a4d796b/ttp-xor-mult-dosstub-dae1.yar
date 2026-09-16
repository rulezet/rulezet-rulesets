rule TTP_XOR_MULT_DOSStub_dae1 {
  strings:
    $key_dae1 = { 8e 89 [2] fa 91 [2] bd 93 [2] fa 82 [2] b4 8e [2] b8 84 [2] af 8f [2] b4 c1 [2] 89 }

  condition:
    any of them
}