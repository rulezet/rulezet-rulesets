rule TTP_XOR_MULT_DOSStub_872a {
  strings:
    $key_872a = { d3 42 [2] a7 5a [2] e0 58 [2] a7 49 [2] e9 45 [2] e5 4f [2] f2 44 [2] e9 0a [2] d4 }

  condition:
    any of them
}