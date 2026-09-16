rule TTP_XOR_MULT_DOSStub_d33c {
  strings:
    $key_d33c = { 87 54 [2] f3 4c [2] b4 4e [2] f3 5f [2] bd 53 [2] b1 59 [2] a6 52 [2] bd 1c [2] 80 }

  condition:
    any of them
}