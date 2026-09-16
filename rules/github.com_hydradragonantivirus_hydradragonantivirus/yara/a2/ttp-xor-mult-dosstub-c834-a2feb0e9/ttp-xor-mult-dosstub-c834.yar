rule TTP_XOR_MULT_DOSStub_c834 {
  strings:
    $key_c834 = { 9c 5c [2] e8 44 [2] af 46 [2] e8 57 [2] a6 5b [2] aa 51 [2] bd 5a [2] a6 14 [2] 9b }

  condition:
    any of them
}