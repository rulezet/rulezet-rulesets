rule TTP_XOR_MULT_DOSStub_c82a {
  strings:
    $key_c82a = { 9c 42 [2] e8 5a [2] af 58 [2] e8 49 [2] a6 45 [2] aa 4f [2] bd 44 [2] a6 0a [2] 9b }

  condition:
    any of them
}