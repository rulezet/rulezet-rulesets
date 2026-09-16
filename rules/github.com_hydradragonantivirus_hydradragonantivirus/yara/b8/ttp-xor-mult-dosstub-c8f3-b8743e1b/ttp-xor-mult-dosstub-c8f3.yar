rule TTP_XOR_MULT_DOSStub_c8f3 {
  strings:
    $key_c8f3 = { 9c 9b [2] e8 83 [2] af 81 [2] e8 90 [2] a6 9c [2] aa 96 [2] bd 9d [2] a6 d3 [2] 9b }

  condition:
    any of them
}