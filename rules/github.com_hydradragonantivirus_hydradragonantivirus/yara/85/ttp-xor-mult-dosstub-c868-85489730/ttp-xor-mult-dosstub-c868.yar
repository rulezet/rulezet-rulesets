rule TTP_XOR_MULT_DOSStub_c868 {
  strings:
    $key_c868 = { 9c 00 [2] e8 18 [2] af 1a [2] e8 0b [2] a6 07 [2] aa 0d [2] bd 06 [2] a6 48 [2] 9b }

  condition:
    any of them
}