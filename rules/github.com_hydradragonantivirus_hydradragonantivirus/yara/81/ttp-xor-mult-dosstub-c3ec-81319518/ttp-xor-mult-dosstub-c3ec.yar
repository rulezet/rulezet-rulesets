rule TTP_XOR_MULT_DOSStub_c3ec {
  strings:
    $key_c3ec = { 97 84 [2] e3 9c [2] a4 9e [2] e3 8f [2] ad 83 [2] a1 89 [2] b6 82 [2] ad cc [2] 90 }

  condition:
    any of them
}