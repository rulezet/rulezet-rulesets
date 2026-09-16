rule TTP_XOR_MULT_DOSStub_89a8 {
  strings:
    $key_89a8 = { dd c0 [2] a9 d8 [2] ee da [2] a9 cb [2] e7 c7 [2] eb cd [2] fc c6 [2] e7 88 [2] da }

  condition:
    any of them
}