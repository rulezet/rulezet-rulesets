rule TTP_XOR_MULT_DOSStub_c859 {
  strings:
    $key_c859 = { 9c 31 [2] e8 29 [2] af 2b [2] e8 3a [2] a6 36 [2] aa 3c [2] bd 37 [2] a6 79 [2] 9b }

  condition:
    any of them
}