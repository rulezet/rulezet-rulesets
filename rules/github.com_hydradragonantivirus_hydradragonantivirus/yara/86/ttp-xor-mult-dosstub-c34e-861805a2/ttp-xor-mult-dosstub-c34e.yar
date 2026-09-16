rule TTP_XOR_MULT_DOSStub_c34e {
  strings:
    $key_c34e = { 97 26 [2] e3 3e [2] a4 3c [2] e3 2d [2] ad 21 [2] a1 2b [2] b6 20 [2] ad 6e [2] 90 }

  condition:
    any of them
}