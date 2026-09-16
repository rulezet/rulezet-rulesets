rule TTP_XOR_MULT_DOSStub_c821 {
  strings:
    $key_c821 = { 9c 49 [2] e8 51 [2] af 53 [2] e8 42 [2] a6 4e [2] aa 44 [2] bd 4f [2] a6 01 [2] 9b }

  condition:
    any of them
}