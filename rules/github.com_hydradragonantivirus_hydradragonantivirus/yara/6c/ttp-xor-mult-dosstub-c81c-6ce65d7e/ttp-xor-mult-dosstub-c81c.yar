rule TTP_XOR_MULT_DOSStub_c81c {
  strings:
    $key_c81c = { 9c 74 [2] e8 6c [2] af 6e [2] e8 7f [2] a6 73 [2] aa 79 [2] bd 72 [2] a6 3c [2] 9b }

  condition:
    any of them
}