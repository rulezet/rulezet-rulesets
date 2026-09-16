rule TTP_XOR_MULT_DOSStub_c22e {
  strings:
    $key_c22e = { 96 46 [2] e2 5e [2] a5 5c [2] e2 4d [2] ac 41 [2] a0 4b [2] b7 40 [2] ac 0e [2] 91 }

  condition:
    any of them
}