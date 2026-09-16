rule TTP_XOR_MULT_DOSStub_8724 {
  strings:
    $key_8724 = { d3 4c [2] a7 54 [2] e0 56 [2] a7 47 [2] e9 4b [2] e5 41 [2] f2 4a [2] e9 04 [2] d4 }

  condition:
    any of them
}