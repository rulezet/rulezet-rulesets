rule TTP_XOR_MULT_DOSStub_c53e {
  strings:
    $key_c53e = { 91 56 [2] e5 4e [2] a2 4c [2] e5 5d [2] ab 51 [2] a7 5b [2] b0 50 [2] ab 1e [2] 96 }

  condition:
    any of them
}