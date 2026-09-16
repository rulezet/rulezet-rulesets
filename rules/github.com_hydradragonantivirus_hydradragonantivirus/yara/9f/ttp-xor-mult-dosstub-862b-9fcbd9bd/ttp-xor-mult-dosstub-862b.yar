rule TTP_XOR_MULT_DOSStub_862b {
  strings:
    $key_862b = { d2 43 [2] a6 5b [2] e1 59 [2] a6 48 [2] e8 44 [2] e4 4e [2] f3 45 [2] e8 0b [2] d5 }

  condition:
    any of them
}