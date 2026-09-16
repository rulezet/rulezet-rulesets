rule TTP_XOR_MULT_DOSStub_c818 {
  strings:
    $key_c818 = { 9c 70 [2] e8 68 [2] af 6a [2] e8 7b [2] a6 77 [2] aa 7d [2] bd 76 [2] a6 38 [2] 9b }

  condition:
    any of them
}