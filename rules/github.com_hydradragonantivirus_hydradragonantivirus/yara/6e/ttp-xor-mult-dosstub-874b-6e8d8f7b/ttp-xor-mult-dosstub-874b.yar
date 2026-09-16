rule TTP_XOR_MULT_DOSStub_874b {
  strings:
    $key_874b = { d3 23 [2] a7 3b [2] e0 39 [2] a7 28 [2] e9 24 [2] e5 2e [2] f2 25 [2] e9 6b [2] d4 }

  condition:
    any of them
}