rule TTP_XOR_MULT_DOSStub_c8f6 {
  strings:
    $key_c8f6 = { 9c 9e [2] e8 86 [2] af 84 [2] e8 95 [2] a6 99 [2] aa 93 [2] bd 98 [2] a6 d6 [2] 9b }

  condition:
    any of them
}