rule TTP_XOR_MULT_DOSStub_c814 {
  strings:
    $key_c814 = { 9c 7c [2] e8 64 [2] af 66 [2] e8 77 [2] a6 7b [2] aa 71 [2] bd 7a [2] a6 34 [2] 9b }

  condition:
    any of them
}