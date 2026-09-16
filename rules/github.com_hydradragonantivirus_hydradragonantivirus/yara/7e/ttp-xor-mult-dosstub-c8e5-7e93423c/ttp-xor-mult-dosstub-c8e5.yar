rule TTP_XOR_MULT_DOSStub_c8e5 {
  strings:
    $key_c8e5 = { 9c 8d [2] e8 95 [2] af 97 [2] e8 86 [2] a6 8a [2] aa 80 [2] bd 8b [2] a6 c5 [2] 9b }

  condition:
    any of them
}