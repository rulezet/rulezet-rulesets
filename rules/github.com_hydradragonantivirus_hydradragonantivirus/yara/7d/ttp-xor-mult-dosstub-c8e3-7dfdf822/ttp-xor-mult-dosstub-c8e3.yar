rule TTP_XOR_MULT_DOSStub_c8e3 {
  strings:
    $key_c8e3 = { 9c 8b [2] e8 93 [2] af 91 [2] e8 80 [2] a6 8c [2] aa 86 [2] bd 8d [2] a6 c3 [2] 9b }

  condition:
    any of them
}