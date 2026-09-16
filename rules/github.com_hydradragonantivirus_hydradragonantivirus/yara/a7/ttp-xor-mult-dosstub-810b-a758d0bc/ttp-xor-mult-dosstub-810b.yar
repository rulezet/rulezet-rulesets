rule TTP_XOR_MULT_DOSStub_810b {
  strings:
    $key_810b = { d5 63 [2] a1 7b [2] e6 79 [2] a1 68 [2] ef 64 [2] e3 6e [2] f4 65 [2] ef 2b [2] d2 }

  condition:
    any of them
}