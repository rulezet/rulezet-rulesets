rule TTP_XOR_MULT_DOSStub_d30b {
  strings:
    $key_d30b = { 87 63 [2] f3 7b [2] b4 79 [2] f3 68 [2] bd 64 [2] b1 6e [2] a6 65 [2] bd 2b [2] 80 }

  condition:
    any of them
}