rule TTP_XOR_MULT_DOSStub_c801 {
  strings:
    $key_c801 = { 9c 69 [2] e8 71 [2] af 73 [2] e8 62 [2] a6 6e [2] aa 64 [2] bd 6f [2] a6 21 [2] 9b }

  condition:
    any of them
}