rule TTP_XOR_MULT_DOSStub_833b {
  strings:
    $key_833b = { d7 53 [2] a3 4b [2] e4 49 [2] a3 58 [2] ed 54 [2] e1 5e [2] f6 55 [2] ed 1b [2] d0 }

  condition:
    any of them
}