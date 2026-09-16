rule TTP_XOR_MULT_DOSStub_c81e {
  strings:
    $key_c81e = { 9c 76 [2] e8 6e [2] af 6c [2] e8 7d [2] a6 71 [2] aa 7b [2] bd 70 [2] a6 3e [2] 9b }

  condition:
    any of them
}