rule TTP_XOR_MULT_DOSStub_d36b {
  strings:
    $key_d36b = { 87 03 [2] f3 1b [2] b4 19 [2] f3 08 [2] bd 04 [2] b1 0e [2] a6 05 [2] bd 4b [2] 80 }

  condition:
    any of them
}