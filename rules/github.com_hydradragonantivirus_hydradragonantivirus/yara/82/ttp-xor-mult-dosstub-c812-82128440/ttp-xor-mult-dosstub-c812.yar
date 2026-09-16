rule TTP_XOR_MULT_DOSStub_c812 {
  strings:
    $key_c812 = { 9c 7a [2] e8 62 [2] af 60 [2] e8 71 [2] a6 7d [2] aa 77 [2] bd 7c [2] a6 32 [2] 9b }

  condition:
    any of them
}