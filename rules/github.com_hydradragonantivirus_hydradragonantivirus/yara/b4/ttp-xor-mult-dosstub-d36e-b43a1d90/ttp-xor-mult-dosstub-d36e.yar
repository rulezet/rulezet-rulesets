rule TTP_XOR_MULT_DOSStub_d36e {
  strings:
    $key_d36e = { 87 06 [2] f3 1e [2] b4 1c [2] f3 0d [2] bd 01 [2] b1 0b [2] a6 00 [2] bd 4e [2] 80 }

  condition:
    any of them
}