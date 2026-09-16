rule TTP_XOR_MULT_DOSStub_c86b {
  strings:
    $key_c86b = { 9c 03 [2] e8 1b [2] af 19 [2] e8 08 [2] a6 04 [2] aa 0e [2] bd 05 [2] a6 4b [2] 9b }

  condition:
    any of them
}