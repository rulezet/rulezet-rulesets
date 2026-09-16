rule TTP_XOR_MULT_DOSStub_c831 {
  strings:
    $key_c831 = { 9c 59 [2] e8 41 [2] af 43 [2] e8 52 [2] a6 5e [2] aa 54 [2] bd 5f [2] a6 11 [2] 9b }

  condition:
    any of them
}