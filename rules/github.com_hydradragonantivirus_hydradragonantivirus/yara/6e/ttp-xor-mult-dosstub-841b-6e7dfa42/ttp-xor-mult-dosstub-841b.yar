rule TTP_XOR_MULT_DOSStub_841b {
  strings:
    $key_841b = { d0 73 [2] a4 6b [2] e3 69 [2] a4 78 [2] ea 74 [2] e6 7e [2] f1 75 [2] ea 3b [2] d7 }

  condition:
    any of them
}