rule TTP_XOR_MULT_DOSStub_c824 {
  strings:
    $key_c824 = { 9c 4c [2] e8 54 [2] af 56 [2] e8 47 [2] a6 4b [2] aa 41 [2] bd 4a [2] a6 04 [2] 9b }

  condition:
    any of them
}