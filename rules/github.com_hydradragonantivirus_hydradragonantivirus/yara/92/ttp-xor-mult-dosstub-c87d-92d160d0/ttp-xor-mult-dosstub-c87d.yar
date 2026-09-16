rule TTP_XOR_MULT_DOSStub_c87d {
  strings:
    $key_c87d = { 9c 15 [2] e8 0d [2] af 0f [2] e8 1e [2] a6 12 [2] aa 18 [2] bd 13 [2] a6 5d [2] 9b }

  condition:
    any of them
}