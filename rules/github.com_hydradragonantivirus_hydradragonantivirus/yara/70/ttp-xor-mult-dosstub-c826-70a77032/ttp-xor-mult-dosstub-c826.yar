rule TTP_XOR_MULT_DOSStub_c826 {
  strings:
    $key_c826 = { 9c 4e [2] e8 56 [2] af 54 [2] e8 45 [2] a6 49 [2] aa 43 [2] bd 48 [2] a6 06 [2] 9b }

  condition:
    any of them
}