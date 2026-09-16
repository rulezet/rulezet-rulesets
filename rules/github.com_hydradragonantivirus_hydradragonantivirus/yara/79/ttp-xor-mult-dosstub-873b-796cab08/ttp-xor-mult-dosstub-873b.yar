rule TTP_XOR_MULT_DOSStub_873b {
  strings:
    $key_873b = { d3 53 [2] a7 4b [2] e0 49 [2] a7 58 [2] e9 54 [2] e5 5e [2] f2 55 [2] e9 1b [2] d4 }

  condition:
    any of them
}