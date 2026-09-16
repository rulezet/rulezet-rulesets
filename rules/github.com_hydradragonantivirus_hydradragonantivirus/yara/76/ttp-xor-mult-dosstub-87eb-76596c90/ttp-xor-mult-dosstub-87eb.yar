rule TTP_XOR_MULT_DOSStub_87eb {
  strings:
    $key_87eb = { d3 83 [2] a7 9b [2] e0 99 [2] a7 88 [2] e9 84 [2] e5 8e [2] f2 85 [2] e9 cb [2] d4 }

  condition:
    any of them
}