rule TTP_XOR_MULT_DOSStub_c806 {
  strings:
    $key_c806 = { 9c 6e [2] e8 76 [2] af 74 [2] e8 65 [2] a6 69 [2] aa 63 [2] bd 68 [2] a6 26 [2] 9b }

  condition:
    any of them
}