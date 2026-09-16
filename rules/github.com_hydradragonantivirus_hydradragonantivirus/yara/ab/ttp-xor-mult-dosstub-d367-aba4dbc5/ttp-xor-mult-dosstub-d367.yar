rule TTP_XOR_MULT_DOSStub_d367 {
  strings:
    $key_d367 = { 87 0f [2] f3 17 [2] b4 15 [2] f3 04 [2] bd 08 [2] b1 02 [2] a6 09 [2] bd 47 [2] 80 }

  condition:
    any of them
}