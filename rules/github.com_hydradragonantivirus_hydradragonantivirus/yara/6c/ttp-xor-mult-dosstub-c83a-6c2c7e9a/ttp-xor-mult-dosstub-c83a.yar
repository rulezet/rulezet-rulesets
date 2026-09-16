rule TTP_XOR_MULT_DOSStub_c83a {
  strings:
    $key_c83a = { 9c 52 [2] e8 4a [2] af 48 [2] e8 59 [2] a6 55 [2] aa 5f [2] bd 54 [2] a6 1a [2] 9b }

  condition:
    any of them
}