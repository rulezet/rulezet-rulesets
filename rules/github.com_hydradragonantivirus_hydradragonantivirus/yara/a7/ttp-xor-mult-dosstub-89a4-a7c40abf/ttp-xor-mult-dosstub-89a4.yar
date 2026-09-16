rule TTP_XOR_MULT_DOSStub_89a4 {
  strings:
    $key_89a4 = { dd cc [2] a9 d4 [2] ee d6 [2] a9 c7 [2] e7 cb [2] eb c1 [2] fc ca [2] e7 84 [2] da }

  condition:
    any of them
}