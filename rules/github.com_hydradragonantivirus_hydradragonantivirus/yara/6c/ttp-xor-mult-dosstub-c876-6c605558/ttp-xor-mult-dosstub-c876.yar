rule TTP_XOR_MULT_DOSStub_c876 {
  strings:
    $key_c876 = { 9c 1e [2] e8 06 [2] af 04 [2] e8 15 [2] a6 19 [2] aa 13 [2] bd 18 [2] a6 56 [2] 9b }

  condition:
    any of them
}