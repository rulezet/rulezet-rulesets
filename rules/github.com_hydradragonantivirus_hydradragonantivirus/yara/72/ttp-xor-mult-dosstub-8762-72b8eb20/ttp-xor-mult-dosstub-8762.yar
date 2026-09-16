rule TTP_XOR_MULT_DOSStub_8762 {
  strings:
    $key_8762 = { d3 0a [2] a7 12 [2] e0 10 [2] a7 01 [2] e9 0d [2] e5 07 [2] f2 0c [2] e9 42 [2] d4 }

  condition:
    any of them
}