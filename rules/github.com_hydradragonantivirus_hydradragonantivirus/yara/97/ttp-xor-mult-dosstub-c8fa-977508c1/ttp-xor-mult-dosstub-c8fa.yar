rule TTP_XOR_MULT_DOSStub_c8fa {
  strings:
    $key_c8fa = { 9c 92 [2] e8 8a [2] af 88 [2] e8 99 [2] a6 95 [2] aa 9f [2] bd 94 [2] a6 da [2] 9b }

  condition:
    any of them
}