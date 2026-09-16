rule TTP_XOR_MULT_DOSStub_c867 {
  strings:
    $key_c867 = { 9c 0f [2] e8 17 [2] af 15 [2] e8 04 [2] a6 08 [2] aa 02 [2] bd 09 [2] a6 47 [2] 9b }

  condition:
    any of them
}