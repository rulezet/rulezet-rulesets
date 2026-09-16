rule TTP_XOR_MULT_DOSStub_dae0 {
  strings:
    $key_dae0 = { 8e 88 [2] fa 90 [2] bd 92 [2] fa 83 [2] b4 8f [2] b8 85 [2] af 8e [2] b4 c0 [2] 89 }

  condition:
    any of them
}