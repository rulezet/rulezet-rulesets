rule TTP_XOR_MULT_DOSStub_843b {
  strings:
    $key_843b = { d0 53 [2] a4 4b [2] e3 49 [2] a4 58 [2] ea 54 [2] e6 5e [2] f1 55 [2] ea 1b [2] d7 }

  condition:
    any of them
}