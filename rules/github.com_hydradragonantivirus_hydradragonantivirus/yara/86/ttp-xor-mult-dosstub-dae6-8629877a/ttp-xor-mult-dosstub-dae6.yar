rule TTP_XOR_MULT_DOSStub_dae6 {
  strings:
    $key_dae6 = { 8e 8e [2] fa 96 [2] bd 94 [2] fa 85 [2] b4 89 [2] b8 83 [2] af 88 [2] b4 c6 [2] 89 }

  condition:
    any of them
}