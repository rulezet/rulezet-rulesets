rule TTP_XOR_MULT_DOSStub_d3ea {
  strings:
    $key_d3ea = { 87 82 [2] f3 9a [2] b4 98 [2] f3 89 [2] bd 85 [2] b1 8f [2] a6 84 [2] bd ca [2] 80 }

  condition:
    any of them
}