rule TTP_XOR_MULT_DOSStub_c838 {
  strings:
    $key_c838 = { 9c 50 [2] e8 48 [2] af 4a [2] e8 5b [2] a6 57 [2] aa 5d [2] bd 56 [2] a6 18 [2] 9b }

  condition:
    any of them
}