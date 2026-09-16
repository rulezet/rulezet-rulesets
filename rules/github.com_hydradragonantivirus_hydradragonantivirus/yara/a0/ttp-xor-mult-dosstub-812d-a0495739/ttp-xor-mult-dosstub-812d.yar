rule TTP_XOR_MULT_DOSStub_812d {
  strings:
    $key_812d = { d5 45 [2] a1 5d [2] e6 5f [2] a1 4e [2] ef 42 [2] e3 48 [2] f4 43 [2] ef 0d [2] d2 }

  condition:
    any of them
}