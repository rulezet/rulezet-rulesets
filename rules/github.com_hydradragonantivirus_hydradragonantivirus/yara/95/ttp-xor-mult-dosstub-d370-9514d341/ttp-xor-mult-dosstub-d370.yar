rule TTP_XOR_MULT_DOSStub_d370 {
  strings:
    $key_d370 = { 87 18 [2] f3 00 [2] b4 02 [2] f3 13 [2] bd 1f [2] b1 15 [2] a6 1e [2] bd 50 [2] 80 }

  condition:
    any of them
}