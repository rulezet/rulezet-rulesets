rule TTP_XOR_MULT_DOSStub_c8ee {
  strings:
    $key_c8ee = { 9c 86 [2] e8 9e [2] af 9c [2] e8 8d [2] a6 81 [2] aa 8b [2] bd 80 [2] a6 ce [2] 9b }

  condition:
    any of them
}