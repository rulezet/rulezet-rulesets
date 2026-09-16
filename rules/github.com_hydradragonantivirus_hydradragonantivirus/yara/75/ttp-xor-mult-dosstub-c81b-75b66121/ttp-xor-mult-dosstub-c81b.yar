rule TTP_XOR_MULT_DOSStub_c81b {
  strings:
    $key_c81b = { 9c 73 [2] e8 6b [2] af 69 [2] e8 78 [2] a6 74 [2] aa 7e [2] bd 75 [2] a6 3b [2] 9b }

  condition:
    any of them
}