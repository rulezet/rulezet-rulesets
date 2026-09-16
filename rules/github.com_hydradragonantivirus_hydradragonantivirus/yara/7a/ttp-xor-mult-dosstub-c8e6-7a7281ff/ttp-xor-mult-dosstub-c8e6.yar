rule TTP_XOR_MULT_DOSStub_c8e6 {
  strings:
    $key_c8e6 = { 9c 8e [2] e8 96 [2] af 94 [2] e8 85 [2] a6 89 [2] aa 83 [2] bd 88 [2] a6 c6 [2] 9b }

  condition:
    any of them
}