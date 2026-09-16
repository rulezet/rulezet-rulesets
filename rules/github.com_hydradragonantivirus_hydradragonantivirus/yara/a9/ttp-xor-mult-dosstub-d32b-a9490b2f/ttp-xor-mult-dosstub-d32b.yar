rule TTP_XOR_MULT_DOSStub_d32b {
  strings:
    $key_d32b = { 87 43 [2] f3 5b [2] b4 59 [2] f3 48 [2] bd 44 [2] b1 4e [2] a6 45 [2] bd 0b [2] 80 }

  condition:
    any of them
}