rule TTP_XOR_MULT_DOSStub_d35b {
  strings:
    $key_d35b = { 87 33 [2] f3 2b [2] b4 29 [2] f3 38 [2] bd 34 [2] b1 3e [2] a6 35 [2] bd 7b [2] 80 }

  condition:
    any of them
}