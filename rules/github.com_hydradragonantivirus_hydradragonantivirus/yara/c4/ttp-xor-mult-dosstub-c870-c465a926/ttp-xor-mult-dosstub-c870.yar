rule TTP_XOR_MULT_DOSStub_c870 {
  strings:
    $key_c870 = { 9c 18 [2] e8 00 [2] af 02 [2] e8 13 [2] a6 1f [2] aa 15 [2] bd 1e [2] a6 50 [2] 9b }

  condition:
    any of them
}