rule TTP_XOR_MULT_DOSStub_c21e {
  strings:
    $key_c21e = { 96 76 [2] e2 6e [2] a5 6c [2] e2 7d [2] ac 71 [2] a0 7b [2] b7 70 [2] ac 3e [2] 91 }

  condition:
    any of them
}