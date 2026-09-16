rule TTP_XOR_MULT_DOSStub_d32e {
  strings:
    $key_d32e = { 87 46 [2] f3 5e [2] b4 5c [2] f3 4d [2] bd 41 [2] b1 4b [2] a6 40 [2] bd 0e [2] 80 }

  condition:
    any of them
}