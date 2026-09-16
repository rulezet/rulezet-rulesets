rule TTP_XOR_MULT_DOSStub_8728 {
  strings:
    $key_8728 = { d3 40 [2] a7 58 [2] e0 5a [2] a7 4b [2] e9 47 [2] e5 4d [2] f2 46 [2] e9 08 [2] d4 }

  condition:
    any of them
}