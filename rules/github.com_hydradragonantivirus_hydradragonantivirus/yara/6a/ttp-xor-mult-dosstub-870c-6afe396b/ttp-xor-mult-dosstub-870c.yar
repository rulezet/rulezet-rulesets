rule TTP_XOR_MULT_DOSStub_870c {
  strings:
    $key_870c = { d3 64 [2] a7 7c [2] e0 7e [2] a7 6f [2] e9 63 [2] e5 69 [2] f2 62 [2] e9 2c [2] d4 }

  condition:
    any of them
}