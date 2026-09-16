rule TTP_XOR_MULT_DOSStub_d35c {
  strings:
    $key_d35c = { 87 34 [2] f3 2c [2] b4 2e [2] f3 3f [2] bd 33 [2] b1 39 [2] a6 32 [2] bd 7c [2] 80 }

  condition:
    any of them
}