rule TTP_XOR_MULT_DOSStub_c835 {
  strings:
    $key_c835 = { 9c 5d [2] e8 45 [2] af 47 [2] e8 56 [2] a6 5a [2] aa 50 [2] bd 5b [2] a6 15 [2] 9b }

  condition:
    any of them
}