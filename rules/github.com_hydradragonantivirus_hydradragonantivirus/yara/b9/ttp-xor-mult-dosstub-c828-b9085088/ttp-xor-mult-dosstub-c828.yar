rule TTP_XOR_MULT_DOSStub_c828 {
  strings:
    $key_c828 = { 9c 40 [2] e8 58 [2] af 5a [2] e8 4b [2] a6 47 [2] aa 4d [2] bd 46 [2] a6 08 [2] 9b }

  condition:
    any of them
}