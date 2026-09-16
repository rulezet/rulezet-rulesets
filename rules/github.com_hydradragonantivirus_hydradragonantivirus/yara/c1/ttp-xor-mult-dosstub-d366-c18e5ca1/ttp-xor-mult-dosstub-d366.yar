rule TTP_XOR_MULT_DOSStub_d366 {
  strings:
    $key_d366 = { 87 0e [2] f3 16 [2] b4 14 [2] f3 05 [2] bd 09 [2] b1 03 [2] a6 08 [2] bd 46 [2] 80 }

  condition:
    any of them
}