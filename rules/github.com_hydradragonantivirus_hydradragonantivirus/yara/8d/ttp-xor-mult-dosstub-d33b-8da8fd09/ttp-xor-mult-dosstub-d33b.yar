rule TTP_XOR_MULT_DOSStub_d33b {
  strings:
    $key_d33b = { 87 53 [2] f3 4b [2] b4 49 [2] f3 58 [2] bd 54 [2] b1 5e [2] a6 55 [2] bd 1b [2] 80 }

  condition:
    any of them
}