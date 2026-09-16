rule TTP_XOR_MULT_DOSStub_c82b {
  strings:
    $key_c82b = { 9c 43 [2] e8 5b [2] af 59 [2] e8 48 [2] a6 44 [2] aa 4e [2] bd 45 [2] a6 0b [2] 9b }

  condition:
    any of them
}