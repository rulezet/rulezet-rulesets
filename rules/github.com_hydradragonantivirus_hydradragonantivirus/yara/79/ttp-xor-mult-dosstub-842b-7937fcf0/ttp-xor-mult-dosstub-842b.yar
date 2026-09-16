rule TTP_XOR_MULT_DOSStub_842b {
  strings:
    $key_842b = { d0 43 [2] a4 5b [2] e3 59 [2] a4 48 [2] ea 44 [2] e6 4e [2] f1 45 [2] ea 0b [2] d7 }

  condition:
    any of them
}