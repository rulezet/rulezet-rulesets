rule TTP_XOR_MULT_DOSStub_c802 {
  strings:
    $key_c802 = { 9c 6a [2] e8 72 [2] af 70 [2] e8 61 [2] a6 6d [2] aa 67 [2] bd 6c [2] a6 22 [2] 9b }

  condition:
    any of them
}