rule TTP_XOR_MULT_DOSStub_8723 {
  strings:
    $key_8723 = { d3 4b [2] a7 53 [2] e0 51 [2] a7 40 [2] e9 4c [2] e5 46 [2] f2 4d [2] e9 03 [2] d4 }

  condition:
    any of them
}