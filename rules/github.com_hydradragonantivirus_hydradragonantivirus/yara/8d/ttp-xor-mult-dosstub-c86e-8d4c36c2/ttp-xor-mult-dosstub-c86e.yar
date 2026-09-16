rule TTP_XOR_MULT_DOSStub_c86e {
  strings:
    $key_c86e = { 9c 06 [2] e8 1e [2] af 1c [2] e8 0d [2] a6 01 [2] aa 0b [2] bd 00 [2] a6 4e [2] 9b }

  condition:
    any of them
}