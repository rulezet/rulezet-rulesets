rule TTP_XOR_MULT_DOSStub_c850 {
  strings:
    $key_c850 = { 9c 38 [2] e8 20 [2] af 22 [2] e8 33 [2] a6 3f [2] aa 35 [2] bd 3e [2] a6 70 [2] 9b }

  condition:
    any of them
}