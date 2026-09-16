rule TTP_XOR_MULT_DOSStub_812c {
  strings:
    $key_812c = { d5 44 [2] a1 5c [2] e6 5e [2] a1 4f [2] ef 43 [2] e3 49 [2] f4 42 [2] ef 0c [2] d2 }

  condition:
    any of them
}