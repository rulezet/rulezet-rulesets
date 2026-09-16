rule TTP_XOR_MULT_DOSStub_c24e {
  strings:
    $key_c24e = { 96 26 [2] e2 3e [2] a5 3c [2] e2 2d [2] ac 21 [2] a0 2b [2] b7 20 [2] ac 6e [2] 91 }

  condition:
    any of them
}