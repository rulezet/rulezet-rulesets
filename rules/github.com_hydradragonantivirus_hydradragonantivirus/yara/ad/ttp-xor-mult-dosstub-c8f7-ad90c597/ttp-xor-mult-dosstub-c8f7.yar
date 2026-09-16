rule TTP_XOR_MULT_DOSStub_c8f7 {
  strings:
    $key_c8f7 = { 9c 9f [2] e8 87 [2] af 85 [2] e8 94 [2] a6 98 [2] aa 92 [2] bd 99 [2] a6 d7 [2] 9b }

  condition:
    any of them
}