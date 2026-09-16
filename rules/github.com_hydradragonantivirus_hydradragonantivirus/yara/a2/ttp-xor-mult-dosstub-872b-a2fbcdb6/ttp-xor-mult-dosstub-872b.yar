rule TTP_XOR_MULT_DOSStub_872b {
  strings:
    $key_872b = { d3 43 [2] a7 5b [2] e0 59 [2] a7 48 [2] e9 44 [2] e5 4e [2] f2 45 [2] e9 0b [2] d4 }

  condition:
    any of them
}