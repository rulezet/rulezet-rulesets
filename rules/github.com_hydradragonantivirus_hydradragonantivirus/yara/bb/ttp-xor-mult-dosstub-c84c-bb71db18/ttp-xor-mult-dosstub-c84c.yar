rule TTP_XOR_MULT_DOSStub_c84c {
  strings:
    $key_c84c = { 9c 24 [2] e8 3c [2] af 3e [2] e8 2f [2] a6 23 [2] aa 29 [2] bd 22 [2] a6 6c [2] 9b }

  condition:
    any of them
}