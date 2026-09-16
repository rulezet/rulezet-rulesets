rule TTP_XOR_MULT_DOSStub_c855 {
  strings:
    $key_c855 = { 9c 3d [2] e8 25 [2] af 27 [2] e8 36 [2] a6 3a [2] aa 30 [2] bd 3b [2] a6 75 [2] 9b }

  condition:
    any of them
}