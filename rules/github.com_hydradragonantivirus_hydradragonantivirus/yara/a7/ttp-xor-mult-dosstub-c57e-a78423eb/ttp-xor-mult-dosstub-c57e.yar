rule TTP_XOR_MULT_DOSStub_c57e {
  strings:
    $key_c57e = { 91 16 [2] e5 0e [2] a2 0c [2] e5 1d [2] ab 11 [2] a7 1b [2] b0 10 [2] ab 5e [2] 96 }

  condition:
    any of them
}