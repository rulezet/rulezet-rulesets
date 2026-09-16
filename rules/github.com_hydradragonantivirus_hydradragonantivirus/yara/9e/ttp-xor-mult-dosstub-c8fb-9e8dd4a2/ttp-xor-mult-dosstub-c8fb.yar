rule TTP_XOR_MULT_DOSStub_c8fb {
  strings:
    $key_c8fb = { 9c 93 [2] e8 8b [2] af 89 [2] e8 98 [2] a6 94 [2] aa 9e [2] bd 95 [2] a6 db [2] 9b }

  condition:
    any of them
}