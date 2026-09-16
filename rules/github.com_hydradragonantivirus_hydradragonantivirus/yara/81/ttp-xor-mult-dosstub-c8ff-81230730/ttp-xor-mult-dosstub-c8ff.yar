rule TTP_XOR_MULT_DOSStub_c8ff {
  strings:
    $key_c8ff = { 9c 97 [2] e8 8f [2] af 8d [2] e8 9c [2] a6 90 [2] aa 9a [2] bd 91 [2] a6 df [2] 9b }

  condition:
    any of them
}