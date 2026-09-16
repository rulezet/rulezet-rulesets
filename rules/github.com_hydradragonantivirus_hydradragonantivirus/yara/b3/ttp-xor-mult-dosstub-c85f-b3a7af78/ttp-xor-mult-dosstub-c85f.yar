rule TTP_XOR_MULT_DOSStub_c85f {
  strings:
    $key_c85f = { 9c 37 [2] e8 2f [2] af 2d [2] e8 3c [2] a6 30 [2] aa 3a [2] bd 31 [2] a6 7f [2] 9b }

  condition:
    any of them
}