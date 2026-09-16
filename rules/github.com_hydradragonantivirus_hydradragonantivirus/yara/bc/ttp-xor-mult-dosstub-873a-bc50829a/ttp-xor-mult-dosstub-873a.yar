rule TTP_XOR_MULT_DOSStub_873a {
  strings:
    $key_873a = { d3 52 [2] a7 4a [2] e0 48 [2] a7 59 [2] e9 55 [2] e5 5f [2] f2 54 [2] e9 1a [2] d4 }

  condition:
    any of them
}