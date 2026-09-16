rule TTP_XOR_MULT_DOSStub_c869 {
  strings:
    $key_c869 = { 9c 01 [2] e8 19 [2] af 1b [2] e8 0a [2] a6 06 [2] aa 0c [2] bd 07 [2] a6 49 [2] 9b }

  condition:
    any of them
}