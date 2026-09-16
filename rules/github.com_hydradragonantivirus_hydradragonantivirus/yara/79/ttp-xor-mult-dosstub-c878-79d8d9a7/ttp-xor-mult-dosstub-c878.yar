rule TTP_XOR_MULT_DOSStub_c878 {
  strings:
    $key_c878 = { 9c 10 [2] e8 08 [2] af 0a [2] e8 1b [2] a6 17 [2] aa 1d [2] bd 16 [2] a6 58 [2] 9b }

  condition:
    any of them
}