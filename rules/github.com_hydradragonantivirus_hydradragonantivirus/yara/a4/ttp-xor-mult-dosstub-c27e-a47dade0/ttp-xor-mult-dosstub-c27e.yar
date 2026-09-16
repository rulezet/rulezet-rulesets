rule TTP_XOR_MULT_DOSStub_c27e {
  strings:
    $key_c27e = { 96 16 [2] e2 0e [2] a5 0c [2] e2 1d [2] ac 11 [2] a0 1b [2] b7 10 [2] ac 5e [2] 91 }

  condition:
    any of them
}