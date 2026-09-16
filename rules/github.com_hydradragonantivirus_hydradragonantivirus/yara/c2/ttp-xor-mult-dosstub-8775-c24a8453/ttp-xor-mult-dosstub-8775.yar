rule TTP_XOR_MULT_DOSStub_8775 {
  strings:
    $key_8775 = { d3 1d [2] a7 05 [2] e0 07 [2] a7 16 [2] e9 1a [2] e5 10 [2] f2 1b [2] e9 55 [2] d4 }

  condition:
    any of them
}