rule TTP_XOR_MULT_DOSStub_d361 {
  strings:
    $key_d361 = { 87 09 [2] f3 11 [2] b4 13 [2] f3 02 [2] bd 0e [2] b1 04 [2] a6 0f [2] bd 41 [2] 80 }

  condition:
    any of them
}