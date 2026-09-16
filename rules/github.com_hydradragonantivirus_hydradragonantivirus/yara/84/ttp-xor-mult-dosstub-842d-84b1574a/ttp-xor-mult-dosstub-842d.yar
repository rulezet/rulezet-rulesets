rule TTP_XOR_MULT_DOSStub_842d {
  strings:
    $key_842d = { d0 45 [2] a4 5d [2] e3 5f [2] a4 4e [2] ea 42 [2] e6 48 [2] f1 43 [2] ea 0d [2] d7 }

  condition:
    any of them
}