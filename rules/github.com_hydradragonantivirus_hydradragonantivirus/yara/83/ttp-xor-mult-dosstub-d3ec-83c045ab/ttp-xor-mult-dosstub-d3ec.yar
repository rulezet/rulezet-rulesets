rule TTP_XOR_MULT_DOSStub_d3ec {
  strings:
    $key_d3ec = { 87 84 [2] f3 9c [2] b4 9e [2] f3 8f [2] bd 83 [2] b1 89 [2] a6 82 [2] bd cc [2] 80 }

  condition:
    any of them
}