rule TTP_XOR_MULT_DOSStub_c85c {
  strings:
    $key_c85c = { 9c 34 [2] e8 2c [2] af 2e [2] e8 3f [2] a6 33 [2] aa 39 [2] bd 32 [2] a6 7c [2] 9b }

  condition:
    any of them
}